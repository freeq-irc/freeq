#![allow(clippy::too_many_arguments)]
//! Per-client connection handler.
//!
//! Each TCP connection gets a [`Connection`] that manages:
//! - IRC registration (NICK/USER)
//! - CAP capability negotiation
//! - SASL authentication flow
//! - Message routing post-registration
//! - WHOIS with DID information
//!
//! The handler is split into submodules for readability:
//! - [`cap`] — CAP negotiation and SASL authentication
//! - [`registration`] — IRC registration completion
//! - [`channel`] — JOIN, PART, MODE, TOPIC, KICK, INVITE, NAMES, LIST
//! - [`messaging`] — PRIVMSG, NOTICE, TAGMSG, CHATHISTORY
//! - [`queries`] — WHOIS, WHO, LUSERS, AWAY
//! - [`helpers`] — S2S broadcast, channel delivery, utility functions

pub(crate) mod act;
mod cap;
mod channel;
pub(crate) mod draft_multiline;
pub mod helpers;
pub(crate) mod login;
pub(crate) mod messaging;
mod policy_cmd;
mod provenance;
mod queries;
pub(crate) mod read_marker;
mod registration;
pub(crate) mod routing;

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::irc::{self, Message};
use crate::server::SharedState;
use base64::Engine;

use cap::{handle_authenticate, handle_cap};
use channel::{
    handle_invite, handle_join, handle_kick, handle_list, handle_mode, handle_names, handle_part,
    handle_topic,
};
use helpers::{normalize_channel, s2s_broadcast, s2s_next_event_id};
use messaging::{handle_chathistory, handle_privmsg, handle_search, handle_tagmsg};
use policy_cmd::handle_policy;
use queries::{handle_away, handle_lusers, handle_who, handle_whois};
use registration::try_complete_registration;

// Re-export items used by other modules in the crate

/// State of a single client connection.
/// Actor class — distinguishes humans from agents in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ActorClass {
    #[default]
    Human,
    Agent,
    ExternalAgent,
}

impl std::fmt::Display for ActorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActorClass::Human => write!(f, "human"),
            ActorClass::Agent => write!(f, "agent"),
            ActorClass::ExternalAgent => write!(f, "external_agent"),
        }
    }
}

/// Structured agent presence state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentPresence {
    pub state: PresenceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    pub updated_at: i64,
}

/// Operational state for agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Online,
    Idle,
    Active,
    Executing,
    WaitingForInput,
    BlockedOnPermission,
    BlockedOnBudget,
    Degraded,
    Paused,
    Sandboxed,
    RateLimited,
    Revoked,
    Offline,
}

impl std::fmt::Display for PresenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        write!(f, "{s}")
    }
}

impl std::str::FromStr for PresenceState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| format!("Unknown presence state: {s}"))
    }
}

impl std::str::FromStr for ActorClass {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human" => Ok(ActorClass::Human),
            "agent" => Ok(ActorClass::Agent),
            "external_agent" => Ok(ActorClass::ExternalAgent),
            _ => Err(format!("Unknown actor class: {s}")),
        }
    }
}

pub struct Connection {
    pub id: String,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub authenticated_did: Option<String>,
    pub registered: bool,
    /// Actor class: human (default), agent, or external_agent.
    pub(crate) actor_class: ActorClass,

    /// Iroh endpoint ID of the remote peer (if connected via iroh).
    /// This is a cryptographic public key, giving us verified identity.
    pub iroh_endpoint_id: Option<String>,

    // CAP negotiation state
    pub(crate) cap_negotiating: bool,
    pub(crate) cap_sasl_requested: bool,
    pub(crate) cap_message_tags: bool,
    pub(crate) cap_multi_prefix: bool,
    pub(crate) cap_echo_message: bool,
    pub(crate) cap_server_time: bool,
    pub(crate) cap_batch: bool,
    /// Client supports IRCv3 `draft/multiline` for sending and receiving
    /// logical messages split across multiple PRIVMSG/NOTICE lines, grouped
    /// inside a BATCH frame. Required for the agent debate flow where LLM
    /// openings/rebuttals routinely exceed the single-PRIVMSG ceiling.
    /// Spec: https://ircv3.net/specs/extensions/multiline
    pub(crate) cap_draft_multiline: bool,
    pub(crate) cap_chathistory: bool,
    pub(crate) cap_account_notify: bool,
    pub(crate) cap_extended_join: bool,
    pub(crate) cap_away_notify: bool,
    /// Client asked for `freeq.at/act`, so it receives task messages. Without
    /// it a client sees only the companion lines, which is what keeps a
    /// human's client from filling with machine traffic it cannot render.
    pub(crate) cap_act: bool,
    pub(crate) cap_account_tag: bool,
    /// Client supports IRCv3 `draft/read-marker` — cross-device read markers
    /// via MARKREAD. See https://ircv3.net/specs/extensions/read-marker.
    pub(crate) cap_read_marker: bool,
    /// Client understands E2EE messages (won't get synthetic notices instead).
    #[allow(dead_code)]
    pub(crate) cap_e2ee: bool,
    /// Server operator (OPER) status.
    pub(crate) is_oper: bool,
    /// Client software identifier (derived from USER realname).
    pub(crate) client_info: Option<String>,
    /// Channels reclaimed from a ghost session, pending synthetic state after registration.
    pub(crate) ghost_channels: Option<Vec<String>>,

    // SASL state
    pub(crate) sasl_in_progress: bool,
    pub(crate) sasl_failures: u8,
    pub(crate) dpop_retries: u8,
}

impl Connection {
    fn new(id: String) -> Self {
        Self {
            id,
            nick: None,
            user: None,
            realname: None,
            authenticated_did: None,
            registered: false,
            actor_class: ActorClass::Human,
            iroh_endpoint_id: None,
            cap_negotiating: false,
            cap_sasl_requested: false,
            cap_message_tags: false,
            cap_multi_prefix: false,
            cap_echo_message: false,
            cap_server_time: false,
            cap_batch: false,
            cap_draft_multiline: false,
            cap_chathistory: false,
            cap_account_notify: false,
            cap_extended_join: false,
            cap_away_notify: false,
            cap_act: false,
            cap_account_tag: false,
            cap_read_marker: false,
            cap_e2ee: false,
            is_oper: false,
            client_info: None,
            ghost_channels: None,
            sasl_in_progress: false,
            sasl_failures: 0,
            dpop_retries: 0,
        }
    }

    pub(crate) fn nick_or_star(&self) -> &str {
        self.nick.as_deref().unwrap_or("*")
    }

    pub(crate) fn hostmask(&self) -> String {
        let nick = self.nick.as_deref().unwrap_or("*");
        let user = self.user.as_deref().unwrap_or("~u");
        let host = self.cloaked_host();
        format!("{nick}!{user}@{host}")
    }

    /// Generate a cloaked hostname.
    /// Authenticated users: shortened DID (e.g. "did/plc/4qsy..xmns")
    /// Guests: "freeq/guest"
    pub(crate) fn cloaked_host(&self) -> String {
        cloak_for_did(self.authenticated_did.as_deref())
    }
}

/// The cloaked hostname for a DID (or a guest, when `None`) — the single
/// derivation shared by live-connection hostmasks and lookups (WHOIS/WHO)
/// that only have a target session's DID in hand.
pub(crate) fn cloak_for_did(did: Option<&str>) -> String {
    if let Some(did) = did {
        // e.g. did:plc:4qsyxmnsblo4luuycm3572bq → freeq/plc/4qsyxmns
        let short = did.strip_prefix("did:").unwrap_or(did);
        let parts: Vec<&str> = short.splitn(2, ':').collect();
        if parts.len() == 2 {
            let method = parts[0];
            let id = &parts[1][..parts[1].len().min(8)];
            format!("freeq/{method}/{id}")
        } else {
            "freeq/did".to_string()
        }
    } else {
        "freeq/guest".to_string()
    }
}

fn is_draft_multiline_rate_exempt(
    msg: &Message,
    state: &Arc<SharedState>,
    session_id: &str,
) -> bool {
    match msg.command.as_str() {
        "BATCH" => is_draft_multiline_batch_rate_exempt(msg, state, session_id),
        "PRIVMSG" | "NOTICE" => is_draft_multiline_chunk_rate_exempt(msg, state, session_id),
        _ => false,
    }
}

fn is_draft_multiline_batch_rate_exempt(
    msg: &Message,
    state: &Arc<SharedState>,
    session_id: &str,
) -> bool {
    let Some(reference) = msg.params.first() else {
        return false;
    };

    if let Some(batch_id) = reference.strip_prefix('+') {
        return is_draft_multiline_batch_open_rate_exempt(msg, state, session_id, batch_id);
    }

    if let Some(batch_id) = reference.strip_prefix('-') {
        return !batch_id.is_empty()
            && state
                .open_batches
                .lock()
                .get(&(session_id.to_string(), batch_id.to_string()))
                .is_some_and(|batch| batch.batch_type == "draft/multiline");
    }

    false
}

fn is_draft_multiline_batch_open_rate_exempt(
    msg: &Message,
    state: &Arc<SharedState>,
    session_id: &str,
    batch_id: &str,
) -> bool {
    if batch_id.is_empty() {
        return false;
    }
    if msg.params.get(1).map(String::as_str) != Some("draft/multiline") {
        return false;
    }
    if msg.params.get(2).is_none_or(|target| target.is_empty()) {
        return false;
    }

    let has_batch = state.cap_batch.lock().contains(session_id);
    let has_multiline = state.cap_draft_multiline.lock().contains(session_id);
    if !has_batch || !has_multiline {
        return false;
    }

    let key = (session_id.to_string(), batch_id.to_string());
    let open = state.open_batches.lock();
    if open.contains_key(&key) {
        return false;
    }

    draft_multiline::count_session_open_batches(&open, session_id)
        < draft_multiline::MAX_CONCURRENT_BATCHES_PER_SESSION
}

fn is_draft_multiline_chunk_rate_exempt(
    msg: &Message,
    state: &Arc<SharedState>,
    session_id: &str,
) -> bool {
    let Some(batch_id) = msg.tags.get("batch") else {
        return false;
    };
    // A real chunk carries a body param; require its presence (matching the
    // PRIVMSG/NOTICE dispatch) without binding it.
    let (Some(target), Some(_)) = (msg.params.first(), msg.params.get(1)) else {
        return false;
    };
    let target = if target.starts_with('#') || target.starts_with('&') {
        normalize_channel(target)
    } else {
        target.clone()
    };

    state
        .open_batches
        .lock()
        .get(&(session_id.to_string(), batch_id.to_string()))
        .is_some_and(|batch| {
            let command_matches = batch
                .first_command
                .as_deref()
                .is_none_or(|seen| seen == msg.command);
            batch.batch_type == "draft/multiline" && batch.target == target && command_matches
        })
}

/// Handle a plain TCP connection.
pub async fn handle(stream: TcpStream, state: Arc<SharedState>) -> Result<()> {
    let peer = stream.peer_addr()?;
    let session_id = format!("{peer}");
    tracing::info!(%session_id, "New connection (plain)");
    let (reader, writer) = tokio::io::split(stream);
    handle_io(BufReader::new(reader), writer, session_id, state).await
}

/// Handle a generic async stream (for TLS, WebSocket, or other wrappers).
pub async fn handle_generic<S>(stream: S, state: Arc<SharedState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_generic_with_meta(stream, state, None).await
}

/// Handle a generic async stream with optional connection metadata.
///
/// `iroh_endpoint_id` is set when the connection comes via iroh transport,
/// providing cryptographic identity for the remote peer.
pub async fn handle_generic_with_meta<S>(
    stream: S,
    state: Arc<SharedState>,
    iroh_endpoint_id: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session_id = format!("stream-{id}");
    tracing::info!(%session_id, iroh_id = ?iroh_endpoint_id, "New connection (generic stream)");
    let (reader, writer) = tokio::io::split(stream);
    handle_io_with_meta(
        BufReader::new(reader),
        writer,
        session_id,
        state,
        iroh_endpoint_id,
    )
    .await
}

async fn handle_io<R, W>(
    reader: BufReader<R>,
    writer: W,
    session_id: String,
    state: Arc<SharedState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_io_with_meta(reader, writer, session_id, state, None).await
}

/// Broadcast the presence change for one left/ended AV slot, close the media
/// room + bridge when the session ended, and persist. Shared by immediate
/// disconnect teardown and the deferred (grace) teardown so both do exactly
/// the same thing. `instance` is the actor's per-device id (empty for legacy).
fn finish_av_slot_teardown(
    state: &Arc<SharedState>,
    av_sid: &str,
    channel: &Option<String>,
    av_nick: &str,
    should_end: bool,
    instance: &str,
) {
    // Media must not outlive the roster slot (audit F6): close this
    // instance's SFU connection(s) so announcement-driven clients stop
    // hearing a roster-ghost. No-op for legacy clients with no instance.
    // (Guard taken and dropped before any av_sessions lock — single
    // lock-order: sfu_state is never held while acquiring av_sessions.)
    #[cfg(feature = "av-native")]
    {
        let sfu = state.sfu_state.lock().clone();
        if let Some(sfu) = sfu {
            sfu.revoke_media(instance);
        }
    }
    if let Some(ch) = channel {
        let participant_count = state.av_sessions.lock().active_participant_count(av_sid);
        if should_end {
            messaging::broadcast_av_state_pub(state, ch, av_sid, "ended", av_nick, "", 0, "");
            // Clean up bridge and Room when the session ends.
            #[cfg(feature = "av-native")]
            {
                state.av_bridges.lock().remove(av_sid);
            }
            let backend = state.av_media.lock().clone();
            let sid = av_sid.to_string();
            if let Some(backend) = backend {
                tokio::spawn(async move {
                    let _ = crate::av_media::MediaBackend::close_room(backend.as_ref(), &sid).await;
                });
            }
        } else {
            messaging::broadcast_av_state_pub(
                state,
                ch,
                av_sid,
                "left",
                av_nick,
                instance,
                participant_count,
                "",
            );
        }
    }
    if let Some(s) = state.av_sessions.lock().get(av_sid) {
        let s = s.clone();
        state.with_db(|db| db.save_av_session(&s));
    }
}

/// One AV participant slot that went away when a connection dropped:
/// `(channel, did, nick, was_publishing, instance)`. The instance is what
/// clients key teardown on, so it has to ride along with the rest.
type AvLeftSession = (String, Option<String>, String, bool, Option<String>);

async fn handle_io_with_meta<R, W>(
    mut reader: BufReader<R>,
    writer: W,
    session_id: String,
    state: Arc<SharedState>,
    iroh_endpoint_id: Option<String>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = Connection::new(session_id.clone());
    conn.iroh_endpoint_id = iroh_endpoint_id;

    // Plugin on_connect hook
    state
        .plugin_manager
        .on_connect(&crate::plugin::ConnectEvent {
            session_id: session_id.clone(),
            remote_addr: session_id.clone(),
        });

    // Channel for sending messages TO this client
    let (tx, mut rx) = mpsc::channel::<String>(16384);
    state.connections.lock().insert(session_id.clone(), tx);

    let server_name = state.server_name.clone();

    // Spawn writer task
    let write_session_id = session_id.clone();
    let mut write_half = writer;
    let write_handle = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(line) = rx.recv().await {
            // Write the first message
            if let Err(e) = write_half.write_all(line.as_bytes()).await {
                tracing::warn!(session_id = %write_session_id, "Write error: {e}");
                break;
            }
            // Drain any queued messages and batch-write them (reduces syscalls)
            let mut batch_count = 0;
            while let Ok(queued) = rx.try_recv() {
                if let Err(e) = write_half.write_all(queued.as_bytes()).await {
                    tracing::warn!(session_id = %write_session_id, "Write error: {e}");
                    return;
                }
                batch_count += 1;
                if batch_count >= 64 {
                    break;
                } // cap batch size
            }
            // Flush after the batch
            if let Err(e) = write_half.flush().await {
                tracing::warn!(session_id = %write_session_id, "Flush error: {e}");
                break;
            }
        }
    });

    // Track whether our own send channel is healthy
    let send_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let send_healthy_ref = send_healthy.clone();
    let send = move |state: &Arc<SharedState>, session_id: &str, msg: String| {
        if let Some(tx) = state.connections.lock().get(session_id)
            && tx.try_send(msg).is_err()
        {
            tracing::warn!(session_id, "Send buffer full or closed");
            send_healthy_ref.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    };

    let mut line_buf = String::new();
    let mut last_activity = tokio::time::Instant::now();
    let ping_interval = tokio::time::Duration::from_secs(30);
    let ping_timeout = tokio::time::Duration::from_secs(60);
    let mut awaiting_pong = false;

    // Eviction signal: the liveness reaper (registration::probe_sibling_liveness)
    // notifies this to force the loop to exit and run normal cleanup.
    let kill_signal = {
        let n = std::sync::Arc::new(tokio::sync::Notify::new());
        state
            .session_kill
            .lock()
            .insert(session_id.clone(), n.clone());
        n
    };

    // Rate limiting: max 10 commands per second, token bucket
    let mut rate_tokens: f64 = 10.0;
    let mut rate_last = tokio::time::Instant::now();
    let rate_max: f64 = 10.0;
    let rate_refill: f64 = 10.0; // tokens per second

    loop {
        // Check if our send channel is dead (buffer full = stuck client)
        if !send_healthy.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!(%session_id, "Send channel unhealthy, disconnecting");
            break;
        }

        line_buf.clear();
        // Cap line length to 8KB to prevent OOM from malicious clients.
        // SECURITY: We use a bounded read that limits memory before data
        // is fully buffered, preventing OOM from clients sending gigabytes
        // without a newline.
        const MAX_LINE_LEN: usize = 8192;
        let read_fut = tokio::time::timeout(ping_interval, async {
            use tokio::io::AsyncBufReadExt as _;
            loop {
                let buf = reader.fill_buf().await?;
                if buf.is_empty() {
                    // EOF
                    return Ok::<usize, std::io::Error>(0);
                }
                // Look for newline in the available buffer
                let len = if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    // Found newline — take up to and including it
                    let chunk = &buf[..=pos];
                    line_buf.push_str(&String::from_utf8_lossy(chunk));
                    pos + 1
                } else {
                    // No newline yet — take the whole buffer
                    let chunk = buf;
                    line_buf.push_str(&String::from_utf8_lossy(chunk));
                    chunk.len()
                };
                reader.consume(len);
                // If we found a newline (line_buf ends with \n), we're done
                if line_buf.ends_with('\n') {
                    return Ok(line_buf.len());
                }
                // If accumulated data exceeds limit, reject
                if line_buf.len() >= MAX_LINE_LEN {
                    return Ok(line_buf.len());
                }
            }
        });
        let read_result = tokio::select! {
            r = read_fut => r,
            _ = kill_signal.notified() => {
                tracing::info!(%session_id, "Session evicted (liveness probe unanswered)");
                break;
            }
        };
        // A completed read whose buffer does NOT end in a newline means the
        // line filled to MAX_LINE_LEN without terminating — it's too long.
        // Checking `ends_with('\n')` (not `len() > MAX_LINE_LEN`) closes an
        // off-by-one: the `BufReader` capacity equals MAX_LINE_LEN, so an
        // oversized line fills to *exactly* the cap, which the old `>` guard
        // let slip through — the line was then parsed and delivered silently
        // truncated instead of rejected. Gate on a completed read (`Ok(Ok(n>0))`)
        // so a slow client's partial line at a ping timeout isn't misread as
        // too long.
        if !line_buf.ends_with('\n') && matches!(&read_result, Ok(Ok(n)) if *n > 0) {
            tracing::warn!(%session_id, len = line_buf.len(), "Line too long, dropping");
            let reply =
                Message::from_server(&server_name, "417", vec!["*", "Input line was too long"]);
            send(&state, &session_id, format!("{reply}\r\n"));
            // Drain remaining bytes up to the next newline to resync.
            // Use bounded drain to avoid the same OOM issue.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                use tokio::io::AsyncBufReadExt as _;
                let mut drained: usize = 0;
                const DRAIN_LIMIT: usize = 1_048_576; // 1MB max drain
                loop {
                    let buf = reader.fill_buf().await?;
                    if buf.is_empty() {
                        break;
                    }
                    let nl_pos = buf.iter().position(|&b| b == b'\n');
                    let consume_len = nl_pos.map(|p| p + 1).unwrap_or(buf.len());
                    reader.consume(consume_len);
                    drained += consume_len;
                    if nl_pos.is_some() || drained >= DRAIN_LIMIT {
                        break;
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .await;
            continue;
        }

        match read_result {
            Ok(Ok(0)) | Ok(Err(_)) => break, // EOF or error
            Err(_) => {
                // Timeout — no data received, send PING or check PONG
                if awaiting_pong {
                    if last_activity.elapsed() > ping_timeout {
                        tracing::info!(%session_id, "Ping timeout");
                        break;
                    }
                } else {
                    let ping = Message::from_server(&server_name, "PING", vec![&server_name]);
                    send(&state, &session_id, format!("{ping}\r\n"));
                    awaiting_pong = true;
                }
                continue;
            }
            Ok(Ok(_)) => {}
        }

        last_activity = tokio::time::Instant::now();

        let Some(msg) = Message::parse(&line_buf) else {
            continue;
        };

        // Rate limiting (skip during registration — clients burst on connect)
        // Exempt read-only and join commands — they burst legitimately on connect
        // when auto-rejoin + client-side JOIN overlap.
        let exempt_from_rate_limit = matches!(
            msg.command.as_str(),
            "JOIN" | "CHATHISTORY" | "WHOIS" | "PING" | "PONG" | "MODE" | "WHO" | "NAMES" | "LOGIN"
        ) || is_draft_multiline_rate_exempt(&msg, &state, &session_id);
        if conn.registered && !exempt_from_rate_limit {
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(rate_last).as_secs_f64();
            rate_tokens = (rate_tokens + elapsed * rate_refill).min(rate_max);
            rate_last = now;
            if rate_tokens < 1.0 {
                tracing::debug!(%session_id, "Rate limited");
                // Warn the user (only once per burst)
                if rate_tokens > -1.0 {
                    let notice = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec!["*", "Flood protection: you are sending commands too fast"],
                    );
                    send(&state, &session_id, format!("{notice}\r\n"));
                }
                continue;
            }
            rate_tokens -= 1.0;
        }

        tracing::debug!(%session_id, "<- {}", line_buf.trim());

        // Check for pending LOGIN completion (from browser OAuth callback)
        if conn.authenticated_did.is_none()
            && let Some(completion) = state.login_completions.lock().remove(&session_id)
        {
            conn.authenticated_did = Some(completion.did.clone());
            // complete_irc_login may have assigned a derived nick on
            // collision; apply it to the connection.
            if let Some(rn) = completion.renamed_nick {
                conn.nick = Some(rn);
            }
            // Trigger auto-op etc. in channels (already handled by complete_irc_login)
        }

        match msg.command.as_str() {
            "CAP" => {
                handle_cap(&mut conn, &msg, &state, &server_name, &session_id, &send);
            }
            "AUTHENTICATE" => {
                handle_authenticate(&mut conn, &msg, &state, &server_name, &session_id, &send)
                    .await;
            }
            "NICK" => {
                if let Some(nick) = msg.params.first() {
                    // Validate nick: 1-64 chars, allowed chars for IRC + AT handles
                    if nick.is_empty()
                        || nick.len() > 64
                        || nick.contains(|c: char| {
                            c.is_control()
                                || c == ' '
                                || c == '\0'
                                || c == '\r'
                                || c == '\n'
                                || c == ','
                                || c == '*'
                                || c == '?'
                                || c == '!'
                                || c == '@'
                                || c == '#'
                                || c == '&'
                                || c == ':'
                        })
                    {
                        let reply = Message::from_server(
                            &server_name,
                            "432",
                            vec![conn.nick_or_star(), nick, "Erroneous Nickname"],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        continue;
                    }
                    let nick_lower = nick.to_lowercase();
                    let in_use_by_session = state
                        .nick_to_session
                        .lock()
                        .get_session(nick)
                        .map(|s| s.to_string());
                    let in_use = in_use_by_session.is_some();

                    // Check if the nick is in use by the same session (case change)
                    // or same DID (multi-device OK)
                    let in_use_by_self = in_use_by_session
                        .as_ref()
                        .is_some_and(|sid| sid == &session_id);
                    let in_use_by_same_did = in_use_by_self
                        || in_use_by_session.as_ref().is_some_and(|sid| {
                            let session_dids = state.session_dids.lock();
                            let my_did = conn.authenticated_did.as_deref();
                            match (session_dids.get(sid), my_did) {
                                (Some(other_did), Some(my)) => other_did == my,
                                _ => false,
                            }
                        });

                    let owner_did = state.nick_owners.lock().get(&nick_lower).cloned();
                    let my_did = conn.authenticated_did.as_deref();
                    let nick_stolen = if conn.cap_negotiating || conn.sasl_in_progress {
                        false
                    } else {
                        owner_did
                            .as_ref()
                            .is_some_and(|owner| my_did.is_none_or(|my| my != owner))
                    };

                    if in_use && !in_use_by_same_did && !in_use_by_self {
                        // During CAP/SASL negotiation, allow the nick if it's owned
                        // by a DID (attach_same_did will handle multi-device at SASL success).
                        let allow_during_negotiation =
                            (conn.cap_negotiating || conn.sasl_in_progress) && owner_did.is_some();
                        if !allow_during_negotiation {
                            let reply = Message::from_server(
                                &server_name,
                                irc::ERR_NICKNAMEINUSE,
                                vec![conn.nick_or_star(), nick, "Nickname is already in use"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        } else {
                            // Stash desired nick — don't insert into nick_to_session yet.
                            // attach_same_did will handle at SASL success.
                            conn.nick = Some(nick.clone());
                        }
                    } else if in_use && in_use_by_same_did && !in_use_by_self {
                        // Same DID, multi-device — allow the nick, just stash it
                        conn.nick = Some(nick.clone());
                    } else if nick_stolen {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NICKNAMEINUSE,
                            vec![
                                conn.nick_or_star(),
                                nick,
                                "Nickname is registered to another identity",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    } else {
                        let old_nick = conn.nick.clone();
                        if let Some(ref old) = old_nick {
                            state.nick_to_session.lock().remove_by_nick(old);
                        }
                        state.nick_to_session.lock().insert(nick, &session_id);
                        conn.nick = Some(nick.clone());

                        if conn.registered {
                            let hostmask = if let Some(ref old) = old_nick {
                                format!(
                                    "{old}!~{}@{}",
                                    conn.user.as_deref().unwrap_or("u"),
                                    conn.cloaked_host()
                                )
                            } else {
                                conn.hostmask()
                            };
                            let nick_msg = format!(":{hostmask} NICK :{nick}\r\n");
                            send(&state, &session_id, nick_msg.clone());

                            let mut notified = std::collections::HashSet::new();
                            notified.insert(session_id.clone());
                            let channels = state.channels.lock();
                            let conns = state.connections.lock();
                            for ch in channels.values() {
                                if ch.members.contains(&session_id) {
                                    for member in &ch.members {
                                        if notified.insert(member.clone())
                                            && let Some(tx) = conns.get(member)
                                        {
                                            let _ = tx.try_send(nick_msg.clone());
                                        }
                                    }
                                }
                            }
                            drop(conns);
                            drop(channels);

                            // Plugin on_nick_change hook
                            if let Some(ref old) = old_nick {
                                state.plugin_manager.on_nick_change(
                                    &crate::plugin::NickChangeEvent {
                                        old_nick: old.clone(),
                                        new_nick: nick.clone(),
                                        did: conn.authenticated_did.clone(),
                                        session_id: session_id.clone(),
                                    },
                                );
                            }

                            // Broadcast to S2S
                            if let Some(ref old) = old_nick {
                                let origin =
                                    state.server_iroh_id.lock().clone().unwrap_or_default();
                                s2s_broadcast(
                                    &state,
                                    crate::s2s::S2sMessage::NickChange {
                                        event_id: s2s_next_event_id(&state),
                                        old: old.clone(),
                                        new: nick.clone(),
                                        origin,
                                    },
                                );
                            }
                        } else {
                            try_complete_registration(
                                &mut conn,
                                &state,
                                &server_name,
                                &session_id,
                                &send,
                            );
                        }
                    }
                }
            }
            "USER" => {
                if msg.params.len() >= 4 {
                    conn.user = Some(msg.params[0].clone());
                    let realname = msg.params[3].clone();
                    // Derive client info from realname
                    let client = detect_client(&realname);
                    state
                        .session_client_info
                        .lock()
                        .insert(session_id.clone(), client.clone());
                    conn.client_info = Some(client);
                    conn.realname = Some(realname);
                    try_complete_registration(&mut conn, &state, &server_name, &session_id, &send);
                }
            }
            "PING" => {
                let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let reply = Message::from_server(&server_name, "PONG", vec![&server_name, token]);
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "PONG" => {
                awaiting_pong = false;
                // Answering any PING proves liveness — clear a pending probe.
                state.liveness_probes.lock().remove(&session_id);
            }
            "JOIN" => {
                if !conn.registered {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NOTREGISTERED,
                        vec![conn.nick_or_star(), "You have not registered"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                if let Some(channels) = msg.params.first() {
                    let keys: Vec<&str> = msg
                        .params
                        .get(1)
                        .map(|k| k.split(',').collect())
                        .unwrap_or_default();
                    for (i, channel) in channels.split(',').enumerate() {
                        let key = keys.get(i).copied();
                        let channel = normalize_channel(channel);
                        handle_join(
                            &conn,
                            &channel,
                            key,
                            &state,
                            &server_name,
                            &session_id,
                            &send,
                        );
                    }
                }
            }
            "PART" => {
                if !conn.registered {
                    continue;
                }
                if let Some(channels) = msg.params.first() {
                    for channel in channels.split(',') {
                        let channel = normalize_channel(channel);
                        handle_part(&conn, &channel, &state, &server_name, &session_id, &send);
                    }
                }
            }
            "MODE" => {
                if !conn.registered {
                    continue;
                }
                if let Some(target) = msg.params.first() {
                    if target.starts_with('#') || target.starts_with('&') {
                        let target = normalize_channel(target);
                        let mode_str = msg.params.get(1).map(|s| s.as_str());
                        let mode_arg = msg.params.get(2).map(|s| s.as_str());
                        handle_mode(
                            &conn,
                            &target,
                            mode_str,
                            mode_arg,
                            &state,
                            &server_name,
                            &session_id,
                            &send,
                        );
                    } else {
                        let reply = Message::from_server(
                            &server_name,
                            "221",
                            vec![conn.nick_or_star(), "+"],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    }
                }
            }
            "INVITE" => {
                if !conn.registered {
                    continue;
                }
                if msg.params.len() >= 2 {
                    let target_nick = &msg.params[0];
                    let channel = normalize_channel(&msg.params[1]);
                    handle_invite(
                        &conn,
                        target_nick,
                        &channel,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "KICK" => {
                if !conn.registered {
                    continue;
                }
                if msg.params.len() >= 2 {
                    let channel = normalize_channel(&msg.params[0]);
                    let target_nick = &msg.params[1];
                    let reason = msg
                        .params
                        .get(2)
                        .map(|s| s.as_str())
                        .unwrap_or(conn.nick_or_star());
                    handle_kick(
                        &conn,
                        &channel,
                        target_nick,
                        reason,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "TOPIC" => {
                if !conn.registered {
                    continue;
                }
                if let Some(channel) = msg.params.first() {
                    let channel = normalize_channel(channel);
                    let new_topic = msg.params.get(1).map(|s| s.as_str());
                    handle_topic(
                        &conn,
                        &channel,
                        new_topic,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "PIN" | "UNPIN" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                if msg.params.len() < 2 {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![nick, &msg.command, "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                let channel = normalize_channel(&msg.params[0]);
                let is_pin = msg.command == "PIN";

                // Check op status (or server oper)
                let is_op = state
                    .channels
                    .lock()
                    .get(&channel)
                    .map(|ch| ch.ops.contains(&session_id))
                    .unwrap_or(false);
                let is_server_oper = state.server_opers.lock().contains(&session_id);
                if !is_op && !is_server_oper {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_CHANOPRIVSNEEDED,
                        vec![nick, &channel, "You're not channel operator"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }

                // Pin the message, not a revision of it: an op pinning after an
                // edit must land on the same entry as one pinning before.
                let msgid = &helpers::root_msgid(&state, &msg.params[1]);

                let mut channels = state.channels.lock();
                if let Some(ch) = channels.get_mut(&channel) {
                    if is_pin {
                        if ch.pins.iter().any(|p| p.msgid == *msgid) {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![
                                    nick,
                                    &format!("Message {msgid} is already pinned in {channel}"),
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        } else {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            ch.pins.insert(
                                0,
                                crate::server::PinnedMessage {
                                    msgid: msgid.to_string(),
                                    pinned_by: nick.to_string(),
                                    pinned_at: now,
                                },
                            );
                            // Cap at 50 pins
                            ch.pins.truncate(50);
                            drop(channels);
                            // Persist to DB (ensure channel exists first)
                            let ch_name = channel.clone();
                            let mid = msgid.to_string();
                            let pinner = nick.to_string();
                            {
                                let channels = state.channels.lock();
                                if let Some(ch) = channels.get(&ch_name) {
                                    let ch_clone = ch.clone();
                                    state.with_db(|db| db.save_channel(&ch_name, &ch_clone));
                                }
                            }
                            state.with_db(|db| db.store_pin(&ch_name, &mid, &pinner, now));
                            // Notify channel with tag for clients to update cache
                            let notice = format!(
                                "@+freeq.at/pin={} :{nick}!~u@host NOTICE {channel} :\x01ACTION pinned a message\x01\r\n",
                                irc::escape_tag_value(msgid)
                            );
                            helpers::broadcast_to_channel(&state, &channel, &notice);
                            // Broadcast to S2S peers
                            helpers::s2s_broadcast(
                                &state,
                                crate::s2s::S2sMessage::Pin {
                                    event_id: helpers::s2s_next_event_id(&state),
                                    channel: channel.clone(),
                                    msgid: msgid.to_string(),
                                    pinned_by: nick.to_string(),
                                    adding: true,
                                    origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                                },
                            );
                        }
                    } else {
                        let before = ch.pins.len();
                        ch.pins.retain(|p| p.msgid != *msgid);
                        if ch.pins.len() < before {
                            drop(channels);
                            // Persist to DB
                            let ch_name = channel.clone();
                            let mid = msgid.to_string();
                            state.with_db(|db| db.remove_pin(&ch_name, &mid));
                            // Notify channel with tag for clients to update cache
                            let notice = format!(
                                "@+freeq.at/unpin={} :{nick}!~u@host NOTICE {channel} :\x01ACTION unpinned a message\x01\r\n",
                                irc::escape_tag_value(msgid)
                            );
                            helpers::broadcast_to_channel(&state, &channel, &notice);
                            // Broadcast to S2S peers
                            helpers::s2s_broadcast(
                                &state,
                                crate::s2s::S2sMessage::Pin {
                                    event_id: helpers::s2s_next_event_id(&state),
                                    channel: channel.clone(),
                                    msgid: msgid.to_string(),
                                    pinned_by: nick.to_string(),
                                    adding: false,
                                    origin: state.server_iroh_id.lock().clone().unwrap_or_default(),
                                },
                            );
                        } else {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![nick, &format!("Message {msgid} is not pinned in {channel}")],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }
                }
            }
            "PINS" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                if let Some(channel) = msg.params.first() {
                    let channel = normalize_channel(channel);
                    let channels = state.channels.lock();
                    if let Some(ch) = channels.get(&channel) {
                        if ch.pins.is_empty() {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![nick, &format!("No pinned messages in {channel}")],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        } else {
                            for pin in &ch.pins {
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![
                                        nick,
                                        &format!(
                                            "PIN {} {} {} {}",
                                            channel, pin.msgid, pin.pinned_by, pin.pinned_at
                                        ),
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                            }
                        }
                    }
                }
            }
            "NAMES" => {
                if !conn.registered {
                    continue;
                }
                if let Some(channel) = msg.params.first() {
                    let channel = normalize_channel(channel);
                    handle_names(&conn, &channel, &state, &server_name, &session_id, &send);
                }
            }
            "WHOIS" => {
                if !conn.registered {
                    continue;
                }
                // Support comma-separated nicks per RFC 2812
                if let Some(target) = msg.params.first() {
                    for nick_target in target.split(',') {
                        let nick_target = nick_target.trim();
                        if !nick_target.is_empty() {
                            handle_whois(
                                &conn,
                                nick_target,
                                &state,
                                &server_name,
                                &session_id,
                                &send,
                            );
                        }
                    }
                }
            }
            "MSGSIG" => {
                // Client registers its session message-signing public key.
                // Usage: MSGSIG <base64url-ed25519-pubkey>
                if !conn.registered {
                    continue;
                }
                if conn.authenticated_did.is_none() {
                    let reply = irc::Message::from_server(
                        &server_name,
                        "FAIL",
                        vec![
                            "MSGSIG",
                            "NOT_AUTHENTICATED",
                            "Must be DID-authenticated to register a signing key",
                        ],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                if let Some(pubkey_b64) = msg.params.first() {
                    use base64::Engine;
                    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pubkey_b64) {
                        Ok(bytes) if bytes.len() == 32 => {
                            match ed25519_dalek::VerifyingKey::from_bytes(
                                bytes.as_slice().try_into().unwrap(),
                            ) {
                                Ok(vk) => {
                                    state.session_msg_keys.lock().insert(session_id.clone(), vk);
                                    if let Some(ref did) = conn.authenticated_did {
                                        state
                                            .did_msg_keys
                                            .lock()
                                            .insert(did.clone(), pubkey_b64.clone());
                                        // Persist to DB so the key survives server restarts
                                        // and is available when the registering DID is offline
                                        // (used by FreeqBotDelegation/v1 cert verification).
                                        let did_for_db = did.clone();
                                        let key_bytes = bytes.clone();
                                        state.with_db(|db| {
                                            db.save_signing_key(&did_for_db, &key_bytes)
                                        });
                                    }
                                    tracing::info!(
                                        session = %session_id,
                                        did = ?conn.authenticated_did,
                                        "Client registered message signing key"
                                    );
                                    let reply = irc::Message::from_server(
                                        &server_name,
                                        "MSGSIG",
                                        vec!["OK"],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                }
                                Err(_) => {
                                    let reply = irc::Message::from_server(
                                        &server_name,
                                        "FAIL",
                                        vec!["MSGSIG", "INVALID_KEY", "Invalid ed25519 public key"],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                }
                            }
                        }
                        _ => {
                            let reply = irc::Message::from_server(
                                &server_name,
                                "FAIL",
                                vec![
                                    "MSGSIG",
                                    "INVALID_KEY",
                                    "Expected 32-byte base64url-encoded ed25519 public key",
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }
                }
            }
            "PRIVMSG" | "NOTICE" => {
                if !conn.registered {
                    continue;
                }
                if let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) {
                    let target = if target.starts_with('#') || target.starts_with('&') {
                        normalize_channel(target)
                    } else {
                        target.clone()
                    };
                    // First: if this message claims membership in an
                    // open `draft/multiline` batch on this connection,
                    // route it into the batch instead of dispatching
                    // immediately. Phase 2 will plug in the on-close
                    // assembly + dispatch.
                    let concat = msg.tags.contains_key("draft/multiline-concat");
                    let routed = draft_multiline::try_route_to_batch(
                        &state,
                        &session_id,
                        &msg.tags,
                        &msg.command,
                        &target,
                        text,
                        concat,
                    );
                    match routed {
                        draft_multiline::RouteOutcome::Absorbed => continue,
                        draft_multiline::RouteOutcome::Error(err) => {
                            draft_multiline::send_batch_error(
                                &state,
                                &server_name,
                                &session_id,
                                &send,
                                &err,
                            );
                            continue;
                        }
                        draft_multiline::RouteOutcome::NotInBatch => {
                            handle_privmsg(&conn, &msg.command, &target, text, &msg.tags, &state);
                        }
                    }
                }
            }
            "BATCH" => {
                if !conn.registered {
                    continue;
                }
                draft_multiline::handle_batch_command(
                    &conn,
                    &msg,
                    &state,
                    &server_name,
                    &session_id,
                    &send,
                );
            }
            "TAGMSG" => {
                if !conn.registered {
                    continue;
                }
                if let Some(target) = msg.params.first() {
                    tracing::info!(
                        nick = %conn.nick_or_star(),
                        target = %target,
                        tags = ?msg.tags.keys().collect::<Vec<_>>(),
                        "TAGMSG received"
                    );
                    handle_tagmsg(&conn, target, &msg.tags, &state);
                }
            }
            "LIST" => {
                if !conn.registered {
                    continue;
                }
                handle_list(&conn, &state, &server_name, &session_id, &send);
            }
            "WHO" => {
                if !conn.registered {
                    continue;
                }
                let target = msg.params.first().map(|s| s.as_str()).unwrap_or("*");
                handle_who(&conn, target, &state, &server_name, &session_id, &send);
            }
            "AWAY" => {
                if !conn.registered {
                    continue;
                }
                let away_msg = msg.params.first().map(|s| s.as_str());
                handle_away(&conn, away_msg, &state, &server_name, &session_id, &send);
            }
            "MARKREAD" => {
                if !conn.registered {
                    continue;
                }
                read_marker::handle_markread(&conn, &msg, &state, &server_name, &session_id, &send);
            }
            "MOTD" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                if let Some(ref motd) = state.config.motd {
                    let start = Message::from_server(
                        &server_name,
                        irc::RPL_MOTDSTART,
                        vec![nick, &format!("- {} Message of the day -", server_name)],
                    );
                    send(&state, &session_id, format!("{start}\r\n"));
                    for line in motd.lines() {
                        let motd_line = Message::from_server(
                            &server_name,
                            irc::RPL_MOTD,
                            vec![nick, &format!("- {line}")],
                        );
                        send(&state, &session_id, format!("{motd_line}\r\n"));
                    }
                    let end = Message::from_server(
                        &server_name,
                        irc::RPL_ENDOFMOTD,
                        vec![nick, "End of /MOTD command"],
                    );
                    send(&state, &session_id, format!("{end}\r\n"));
                } else {
                    let no_motd = Message::from_server(
                        &server_name,
                        irc::ERR_NOMOTD,
                        vec![nick, "MOTD File is missing"],
                    );
                    send(&state, &session_id, format!("{no_motd}\r\n"));
                }
            }
            "CHATHISTORY" => {
                if !conn.registered {
                    continue;
                }
                handle_chathistory(&conn, &msg, &state, &server_name, &session_id, &send);
            }
            "SEARCH" => {
                if !conn.registered {
                    continue;
                }
                handle_search(&conn, &msg, &state, &server_name, &session_id, &send);
            }
            "VERSION" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                let reply = Message::from_server(
                    &server_name,
                    irc::RPL_VERSION,
                    vec![
                        nick,
                        &format!("freeq-{}-{}", env!("CARGO_PKG_VERSION"), env!("GIT_HASH")),
                        &server_name,
                        "AT Protocol SASL, IRCv3, iroh QUIC, S2S federation",
                    ],
                );
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "TIME" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                let now = chrono::Utc::now()
                    .format("%a %b %d %Y %H:%M:%S UTC")
                    .to_string();
                let reply = Message::from_server(
                    &server_name,
                    irc::RPL_TIME,
                    vec![nick, &server_name, &now],
                );
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "LUSERS" => {
                if !conn.registered {
                    continue;
                }
                handle_lusers(&conn, &state, &server_name, &session_id, &send);
            }
            "USERHOST" => {
                if !conn.registered {
                    continue;
                }
                let mut replies = Vec::new();
                for nick in msg.params.iter().take(5) {
                    let n2s = state.nick_to_session.lock();
                    if let Some(sid) = n2s.get_session(nick) {
                        let sid = sid.to_string();
                        let is_op = {
                            let channels = state.channels.lock();
                            channels.values().any(|ch| ch.ops.contains(&sid))
                        };
                        let prefix = if is_op { "*" } else { "" };
                        let did = state.session_dids.lock().get(&sid).cloned();
                        let host = helpers::cloaked_host_for_did(did.as_deref());
                        replies.push(format!("{nick}{prefix}=+{nick}@{host}"));
                    }
                }
                let reply = Message::from_server(
                    &server_name,
                    irc::RPL_USERHOST,
                    vec![conn.nick_or_star(), &replies.join(" ")],
                );
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "ISON" => {
                if !conn.registered {
                    continue;
                }
                let n2s = state.nick_to_session.lock();
                let online: Vec<&str> = msg
                    .params
                    .iter()
                    .filter(|nick| n2s.contains_nick(nick))
                    .map(|s| s.as_str())
                    .collect();
                let reply = Message::from_server(
                    &server_name,
                    irc::RPL_ISON,
                    vec![conn.nick_or_star(), &online.join(" ")],
                );
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "ADMIN" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                let r1 = Message::from_server(
                    &server_name,
                    irc::RPL_ADMINME,
                    vec![nick, &server_name, "Administrative info"],
                );
                let r2 = Message::from_server(
                    &server_name,
                    irc::RPL_ADMINLOC1,
                    vec![nick, "freeq IRC server"],
                );
                let r3 = Message::from_server(
                    &server_name,
                    irc::RPL_ADMINLOC2,
                    vec![nick, "AT Protocol authenticated IRC"],
                );
                let r4 = Message::from_server(
                    &server_name,
                    irc::RPL_ADMINEMAIL,
                    vec![nick, "https://freeq.at"],
                );
                for r in [r1, r2, r3, r4] {
                    send(&state, &session_id, format!("{r}\r\n"));
                }
            }
            "INFO" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star();
                let lines = [
                    "freeq - IRC with AT Protocol identity",
                    "",
                    "https://freeq.at",
                    "https://github.com/freeq-irc/freeq",
                    "",
                    "SASL ATPROTO-CHALLENGE authentication",
                    "IRCv3 capabilities, E2EE channels, iroh QUIC transport",
                    "Server-to-server federation with CRDT convergence",
                ];
                for line in &lines {
                    let r = Message::from_server(&server_name, irc::RPL_INFO, vec![nick, line]);
                    send(&state, &session_id, format!("{r}\r\n"));
                }
                let end = Message::from_server(
                    &server_name,
                    irc::RPL_ENDOFINFO,
                    vec![nick, "End of /INFO list"],
                );
                send(&state, &session_id, format!("{end}\r\n"));
            }
            "LOGIN" => {
                if !conn.registered {
                    continue;
                }
                let handle = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                login::handle_login(&mut conn, handle, &state, &server_name, &session_id, &send);
            }
            "POLICY" => {
                if !conn.registered {
                    continue;
                }
                handle_policy(&conn, &msg, &state, &server_name, &session_id, &send);
            }
            "OPER" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                if msg.params.len() < 2 {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![&nick, "OPER", "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                let _name = &msg.params[0]; // oper name (unused — we just check password)
                let password = &msg.params[1];
                let granted = if let Some(ref oper_pw) = state.config.oper_password {
                    constant_time_eq(password.as_bytes(), oper_pw.as_bytes())
                } else {
                    false
                };
                if granted {
                    conn.is_oper = true;
                    state.server_opers.lock().insert(session_id.clone());
                    let reply = Message::from_server(
                        &server_name,
                        "381",
                        vec![&nick, "You are now an IRC operator"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    tracing::info!(nick = %nick, session = %session_id, "OPER granted");
                } else {
                    let reply = Message::from_server(
                        &server_name,
                        "464",
                        vec![&nick, "Password incorrect"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    tracing::warn!(nick = %nick, session = %session_id, "OPER failed: bad password");
                }
            }
            // AGENT command — register as an agent or manage agent state.
            // Usage: AGENT REGISTER :class=agent
            "AGENT" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                if msg.params.is_empty() {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![&nick, "AGENT", "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                let subcmd = msg.params[0].to_uppercase();
                match subcmd.as_str() {
                    "REGISTER" => {
                        // Parse class from trailing param: "class=agent"
                        let class_str = msg
                            .params
                            .get(1)
                            .and_then(|p| p.strip_prefix("class="))
                            .unwrap_or("agent");
                        match class_str.parse::<ActorClass>() {
                            Ok(class) => {
                                conn.actor_class = class;
                                // Store in shared state for WHOIS / member list lookups
                                state
                                    .session_actor_class
                                    .lock()
                                    .insert(session_id.clone(), class);
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![&nick, &format!("Agent registered as {class}")],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                tracing::info!(nick = %nick, session = %session_id, actor_class = %class, "AGENT REGISTER");

                                // Broadcast actor class to shared channels if they support the cap
                                if conn.cap_message_tags {
                                    let hostmask = conn.hostmask();
                                    // Collect targets first, then send (avoid holding multiple locks)
                                    let targets: Vec<(String, Vec<String>)> = {
                                        let channels = state.channels.lock();
                                        channels
                                            .iter()
                                            .filter(|(_, ch)| ch.members.contains(&session_id))
                                            .map(|(ch_name, ch)| {
                                                let members: Vec<String> = ch
                                                    .members
                                                    .iter()
                                                    .filter(|sid| *sid != &session_id)
                                                    .cloned()
                                                    .collect();
                                                (ch_name.clone(), members)
                                            })
                                            .collect()
                                    };
                                    let conns = state.connections.lock();
                                    for (ch_name, members) in &targets {
                                        let msg_line = format!(
                                            "@+freeq.at/actor-class={class} :{hostmask} NOTICE {ch_name} :registered as {class}\r\n"
                                        );
                                        for member_sid in members {
                                            if let Some(tx) = conns.get(member_sid) {
                                                let _ = tx.try_send(msg_line.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![&nick, &format!("Invalid actor class: {e}")],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                            }
                        }
                    }
                    // ── Phase 2: Governance signals ──────────────────
                    // AGENT PAUSE <nick> [reason]
                    "PAUSE" | "RESUME" | "REVOKE" => {
                        let target_nick = match msg.params.get(1) {
                            Some(n) => n.clone(),
                            None => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NEEDMOREPARAMS,
                                    vec![
                                        &nick,
                                        "AGENT",
                                        "Usage: AGENT PAUSE/RESUME/REVOKE <nick> [reason]",
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };
                        let reason = msg.params.get(2).cloned();
                        let action = subcmd.to_lowercase();

                        // Find target session
                        let target_session = state
                            .nick_to_session
                            .lock()
                            .get_session(&target_nick)
                            .map(|s| s.to_string());
                        let target_session = match target_session {
                            Some(s) => s,
                            None => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NOSUCHNICK,
                                    vec![&nick, &target_nick, "No such nick"],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };

                        // Verify sender is op in a shared channel OR server oper
                        let is_oper = conn.is_oper;
                        let is_op_in_shared = {
                            let channels = state.channels.lock();
                            channels.values().any(|ch| {
                                ch.members.contains(&session_id)
                                    && ch.members.contains(&target_session)
                                    && ch.ops.contains(&session_id)
                            })
                        };
                        if !is_oper && !is_op_in_shared {
                            let reply = Message::from_server(
                                &server_name,
                                "482",
                                vec![&nick, "You must be an op in a shared channel"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        }

                        // Send governance TAGMSG to the target agent
                        let reason_tag = reason
                            .as_deref()
                            .map(|r| format!(";+freeq.at/reason={}", irc::escape_tag_value(r)))
                            .unwrap_or_default();
                        let hostmask = conn.hostmask();
                        let gov_msg = format!(
                            "@+freeq.at/governance={action};+freeq.at/issued-by={}{reason_tag} :{hostmask} TAGMSG {target_nick}\r\n",
                            nick
                        );
                        if let Some(tx) = state.connections.lock().get(&target_session) {
                            let _ = tx.try_send(gov_msg);
                        }

                        // Broadcast human-readable notice to shared channels
                        let emoji = match action.as_str() {
                            "pause" => "⏸",
                            "resume" => "▶",
                            "revoke" => "❌",
                            _ => "🔧",
                        };
                        let reason_str = reason
                            .as_deref()
                            .map(|r| format!(": {r}"))
                            .unwrap_or_default();
                        let notice_text =
                            format!("{emoji} {target_nick} {action}d by {nick}{reason_str}");
                        {
                            let shared_channels: Vec<String> = {
                                let channels = state.channels.lock();
                                channels
                                    .iter()
                                    .filter(|(_, ch)| {
                                        ch.members.contains(&session_id)
                                            && ch.members.contains(&target_session)
                                    })
                                    .map(|(name, _)| name.clone())
                                    .collect()
                            };
                            for ch_name in &shared_channels {
                                helpers::broadcast_to_channel(
                                    &state,
                                    ch_name,
                                    &format!(":{server_name} NOTICE {ch_name} :{notice_text}\r\n"),
                                );
                            }
                        }

                        // Log to DB
                        let target_did = state.session_dids.lock().get(&target_session).cloned();
                        if let Some(ref did) = target_did {
                            let issuer_did = conn.authenticated_did.as_deref().unwrap_or(&nick);
                            state.with_db(|db| {
                                db.log_governance(None, did, &action, issuer_did, reason.as_deref())
                            });
                        }

                        // For REVOKE: also revoke all capabilities and force part
                        if action == "revoke" {
                            if let Some(ref did) = target_did {
                                let channels: Vec<String> = {
                                    let chs = state.channels.lock();
                                    chs.iter()
                                        .filter(|(_, ch)| ch.members.contains(&target_session))
                                        .map(|(name, _)| name.clone())
                                        .collect()
                                };
                                for ch in &channels {
                                    state.with_db(|db| db.revoke_all_capabilities(ch, did));
                                }
                            }
                            // Send ERROR to force disconnect
                            if let Some(tx) = state.connections.lock().get(&target_session) {
                                let _ = tx
                                    .try_send(format!("ERROR :Revoked by {nick}{reason_str}\r\n"));
                            }
                        }

                        tracing::info!(action = %action, target = %target_nick, by = %nick, "AGENT governance");
                    }

                    // AGENT APPROVE <nick> <capability>
                    "APPROVE" => {
                        let (target_nick, capability) = match (msg.params.get(1), msg.params.get(2))
                        {
                            (Some(n), Some(c)) => (n.clone(), c.clone()),
                            _ => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NEEDMOREPARAMS,
                                    vec![
                                        &nick,
                                        "AGENT",
                                        "Usage: AGENT APPROVE <nick> <capability>",
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };

                        let target_did = {
                            let ts = state
                                .nick_to_session
                                .lock()
                                .get_session(&target_nick)
                                .map(|s| s.to_string());
                            ts.and_then(|sid| state.session_dids.lock().get(&sid).cloned())
                        };

                        if let Some(ref did) = target_did {
                            let issuer_did = conn.authenticated_did.as_deref().unwrap_or(&nick);
                            // Find pending approval in any shared channel
                            let approval = {
                                let shared: Vec<String> = {
                                    let channels = state.channels.lock();
                                    channels.keys().cloned().collect()
                                };
                                shared.into_iter().find_map(|ch| {
                                    state
                                        .with_db(|db| {
                                            Ok(db.find_pending_approval_for_agent(
                                                &ch,
                                                did,
                                                &capability,
                                            ))
                                        })
                                        .flatten()
                                })
                            };

                            if let Some(approval) = approval {
                                let granted = state
                                    .with_db(|db| db.grant_approval(&approval.id, issuer_did))
                                    .unwrap_or(false);
                                if granted {
                                    // Notify agent
                                    let target_session = state
                                        .nick_to_session
                                        .lock()
                                        .get_session(&target_nick)
                                        .map(|s| s.to_string());
                                    if let Some(ref ts) = target_session {
                                        let line = format!(
                                            "@+freeq.at/governance=approval_granted;+freeq.at/capability={} :{server_name} TAGMSG {target_nick}\r\n",
                                            irc::escape_tag_value(&capability)
                                        );
                                        if let Some(tx) = state.connections.lock().get(ts) {
                                            let _ = tx.try_send(line);
                                        }
                                    }
                                    // Notify channel
                                    let notice = format!(
                                        ":{server_name} NOTICE {} :✅ {nick} approved '{capability}' for {target_nick}\r\n",
                                        approval.channel
                                    );
                                    helpers::broadcast_to_channel(
                                        &state,
                                        &approval.channel,
                                        &notice,
                                    );

                                    state.with_db(|db| {
                                        db.log_governance(
                                            Some(&approval.channel),
                                            did,
                                            "approve",
                                            issuer_did,
                                            Some(&capability),
                                        )
                                    });
                                    tracing::info!(target = %target_nick, capability = %capability, by = %nick, "Approval granted");
                                }
                            } else {
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![
                                        &nick,
                                        &format!(
                                            "No pending approval for {target_nick}/{capability}"
                                        ),
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                            }
                        } else {
                            let reply = Message::from_server(
                                &server_name,
                                irc::ERR_NOSUCHNICK,
                                vec![&nick, &target_nick, "No such nick or not authenticated"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }

                    // AGENT DENY <nick> <capability> [reason]
                    "DENY" => {
                        let (target_nick, capability) = match (msg.params.get(1), msg.params.get(2))
                        {
                            (Some(n), Some(c)) => (n.clone(), c.clone()),
                            _ => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NEEDMOREPARAMS,
                                    vec![
                                        &nick,
                                        "AGENT",
                                        "Usage: AGENT DENY <nick> <capability> [reason]",
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };
                        let reason = msg.params.get(3).cloned();
                        let target_did = {
                            let ts = state
                                .nick_to_session
                                .lock()
                                .get_session(&target_nick)
                                .map(|s| s.to_string());
                            ts.and_then(|sid| state.session_dids.lock().get(&sid).cloned())
                        };

                        if let Some(ref did) = target_did {
                            let issuer_did = conn.authenticated_did.as_deref().unwrap_or(&nick);
                            let shared: Vec<String> =
                                state.channels.lock().keys().cloned().collect();
                            let approval = shared.into_iter().find_map(|ch| {
                                state
                                    .with_db(|db| {
                                        Ok(db.find_pending_approval_for_agent(
                                            &ch,
                                            did,
                                            &capability,
                                        ))
                                    })
                                    .flatten()
                            });

                            if let Some(approval) = approval {
                                let denied = state
                                    .with_db(|db| {
                                        db.deny_approval(
                                            &approval.id,
                                            issuer_did,
                                            reason.as_deref(),
                                        )
                                    })
                                    .unwrap_or(false);
                                if denied {
                                    let target_session = state
                                        .nick_to_session
                                        .lock()
                                        .get_session(&target_nick)
                                        .map(|s| s.to_string());
                                    if let Some(ref ts) = target_session {
                                        let reason_tag = reason
                                            .as_deref()
                                            .map(|r| {
                                                format!(
                                                    ";+freeq.at/reason={}",
                                                    irc::escape_tag_value(r)
                                                )
                                            })
                                            .unwrap_or_default();
                                        let line = format!(
                                            "@+freeq.at/governance=approval_denied;+freeq.at/capability={}{reason_tag} :{server_name} TAGMSG {target_nick}\r\n",
                                            irc::escape_tag_value(&capability)
                                        );
                                        if let Some(tx) = state.connections.lock().get(ts) {
                                            let _ = tx.try_send(line);
                                        }
                                    }
                                    let reason_str = reason
                                        .as_deref()
                                        .map(|r| format!(": {r}"))
                                        .unwrap_or_default();
                                    let notice = format!(
                                        ":{server_name} NOTICE {} :❌ {nick} denied '{capability}' for {target_nick}{reason_str}\r\n",
                                        approval.channel
                                    );
                                    helpers::broadcast_to_channel(
                                        &state,
                                        &approval.channel,
                                        &notice,
                                    );
                                    tracing::info!(target = %target_nick, capability = %capability, by = %nick, "Approval denied");
                                }
                            }
                        }
                    }

                    // ── Phase 4: Manifests ──────────────────────────
                    // AGENT MANIFEST <url-or-inline-toml>
                    "MANIFEST" => {
                        let raw = msg.params.get(1).cloned().unwrap_or_default();
                        if raw.is_empty() {
                            let reply = Message::from_server(
                                &server_name,
                                irc::ERR_NEEDMOREPARAMS,
                                vec![&nick, "AGENT", "Usage: AGENT MANIFEST <url-or-inline-toml>"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        }

                        // Try to parse as TOML first, then as URL
                        let manifest_result =
                            if raw.starts_with("http://") || raw.starts_with("https://") {
                                // URL — we don't fetch in tests, just store the URL
                                Err("URL manifests require REST API".to_string())
                            } else {
                                // Inline TOML (base64-encoded to survive IRC)
                                use base64::Engine;
                                match base64::engine::general_purpose::STANDARD.decode(&raw) {
                                    Ok(bytes) => match String::from_utf8(bytes) {
                                        Ok(toml_str) => {
                                            crate::manifest::AgentManifest::from_toml(&toml_str)
                                                .map_err(|e| format!("Invalid TOML: {e}"))
                                        }
                                        Err(e) => Err(format!("Invalid UTF-8: {e}")),
                                    },
                                    Err(_) => crate::manifest::AgentManifest::from_toml(&raw)
                                        .map_err(|e| format!("Invalid TOML: {e}")),
                                }
                            };

                        match manifest_result {
                            Ok(manifest) => {
                                if let Err(e) = manifest.validate() {
                                    let reply = Message::from_server(
                                        &server_name,
                                        "NOTICE",
                                        vec![&nick, &format!("Invalid manifest: {e}")],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                    continue;
                                }
                                let agent_did =
                                    conn.authenticated_did.as_deref().unwrap_or("unknown");
                                let registrar = conn.authenticated_did.as_deref().unwrap_or(&nick);
                                let manifest_json = manifest.to_json();
                                state.with_db(|db| {
                                    db.save_manifest(agent_did, &manifest_json, None, registrar)
                                });

                                // Auto-apply: set actor class + provenance
                                if let Ok(class) = manifest.agent.actor_class.parse::<ActorClass>()
                                {
                                    conn.actor_class = class;
                                    state
                                        .session_actor_class
                                        .lock()
                                        .insert(session_id.clone(), class);
                                }

                                let caps = manifest.capabilities.default.join(", ");
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![
                                        &nick,
                                        &format!(
                                            "✅ Manifest registered for {}. Capabilities: {caps}",
                                            manifest.agent.display_name
                                        ),
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                tracing::info!(nick = %nick, display_name = %manifest.agent.display_name, "AGENT MANIFEST registered");
                            }
                            Err(e) => {
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![&nick, &format!("Manifest error: {e}")],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                            }
                        }
                    }

                    // ── Phase 4: Spawn ──────────────────────────────
                    // AGENT SPAWN #channel :nick=child;capabilities=cap1,cap2;ttl=300;task=01JQXYZ
                    "SPAWN" => {
                        let channel = match msg.params.get(1) {
                            Some(c) if c.starts_with('#') => c.clone(),
                            _ => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NEEDMOREPARAMS,
                                    vec![
                                        &nick,
                                        "AGENT",
                                        "Usage: AGENT SPAWN #channel :nick=name;capabilities=a,b;ttl=300;task=id",
                                    ],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };
                        let params_str = msg.params.get(2).cloned().unwrap_or_default();
                        let mut child_nick = String::new();
                        let mut capabilities: Vec<String> = Vec::new();
                        let mut ttl: Option<u64> = None;
                        let mut task_ref: Option<String> = None;
                        for part in params_str.split(';') {
                            if let Some((k, v)) = part.split_once('=') {
                                match k.trim() {
                                    "nick" => child_nick = v.trim().to_string(),
                                    "capabilities" => {
                                        capabilities =
                                            v.split(',').map(|s| s.trim().to_string()).collect()
                                    }
                                    "ttl" => ttl = v.trim().parse().ok(),
                                    "task" => task_ref = Some(v.trim().to_string()),
                                    _ => {}
                                }
                            }
                        }
                        if child_nick.is_empty() {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![&nick, "SPAWN requires nick= parameter"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        }

                        // Check nick availability
                        if state
                            .nick_to_session
                            .lock()
                            .get_session(&child_nick)
                            .is_some()
                        {
                            let reply = Message::from_server(
                                &server_name,
                                "433",
                                vec![&nick, &child_nick, "Nickname already in use"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        }

                        // Generate session-scoped DID for child
                        let child_did = format!("did:freeq:spawn:{}", crate::msgid::generate());
                        let parent_did = conn
                            .authenticated_did
                            .clone()
                            .unwrap_or_else(|| nick.clone());

                        // Narrow to what the parent actually holds (PHASE-4 step 5).
                        //
                        // You cannot delegate authority you do not have. Without
                        // this the requested list was recorded verbatim, so a
                        // parent holding nothing could create a child holding
                        // "deploy, admin". A parent that declares no capabilities
                        // confers none.
                        let requested = capabilities.clone();
                        let capabilities = state
                            .with_db(|db| {
                                Ok(db.narrow_capabilities(&channel, &parent_did, &requested))
                            })
                            .unwrap_or_default();
                        let refused: Vec<&String> = requested
                            .iter()
                            .filter(|r| !capabilities.contains(r))
                            .collect();
                        if !refused.is_empty() {
                            tracing::info!(
                                parent = %parent_did, child = %child_nick, channel = %channel,
                                refused = ?refused,
                                "Spawn capabilities narrowed: parent does not hold these"
                            );
                            let notice = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![
                                    &nick,
                                    &format!(
                                        "Not conferred (you do not hold): {}",
                                        refused
                                            .iter()
                                            .map(|s| s.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ),
                                ],
                            );
                            send(&state, &session_id, format!("{notice}\r\n"));
                        }

                        // Record spawn
                        state.with_db(|db| {
                            db.record_spawn(
                                &child_did,
                                &parent_did,
                                &session_id,
                                &child_nick,
                                &channel,
                                &capabilities,
                                ttl,
                                task_ref.as_deref(),
                            )
                        });

                        // Store in spawned_agents map (in-memory for fast lookup)
                        state.spawned_agents.lock().insert(
                            child_did.clone(),
                            crate::server::SpawnedAgent {
                                child_did: child_did.clone(),
                                parent_did: parent_did.clone(),
                                parent_session: session_id.clone(),
                                nick: child_nick.clone(),
                                channel: channel.clone(),
                                capabilities: capabilities.clone(),
                                ttl,
                                task_ref: task_ref.clone(),
                                spawned_at: chrono::Utc::now().timestamp(),
                            },
                        );

                        // Broadcast JOIN for child to channel
                        let child_hostmask = format!(
                            "{child_nick}!spawn@freeq/spawn/{}",
                            &child_did[child_did.len().saturating_sub(8)..]
                        );
                        let join_line = format!(
                            "@+freeq.at/actor-class=agent;+freeq.at/parent={} :{child_hostmask} JOIN {channel}\r\n",
                            nick
                        );
                        helpers::broadcast_to_channel(&state, &channel, &join_line);

                        // Set up TTL expiry
                        if let Some(ttl_secs) = ttl {
                            let state_clone = Arc::clone(&state);
                            let child_did_clone = child_did.clone();
                            let child_nick_clone = child_nick.clone();
                            let channel_clone = channel.clone();
                            let server_name_clone = server_name.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(ttl_secs)).await;
                                // Auto-despawn
                                if state_clone
                                    .spawned_agents
                                    .lock()
                                    .remove(&child_did_clone)
                                    .is_some()
                                {
                                    let quit_line = format!(
                                        ":{child_nick_clone}!spawn@freeq/spawn QUIT :TTL expired\r\n"
                                    );
                                    helpers::broadcast_to_channel(
                                        &state_clone,
                                        &channel_clone,
                                        &quit_line,
                                    );
                                    let notice = format!(
                                        ":{server_name_clone} NOTICE {channel_clone} :⏱ Spawned agent {child_nick_clone} expired (TTL)\r\n"
                                    );
                                    helpers::broadcast_to_channel(
                                        &state_clone,
                                        &channel_clone,
                                        &notice,
                                    );
                                    state_clone.with_db(|db| db.record_despawn(&child_did_clone));
                                    tracing::info!(child = %child_nick_clone, "Spawned agent TTL expired");
                                }
                            });
                        }

                        let caps_str = if capabilities.is_empty() {
                            "none".to_string()
                        } else {
                            capabilities.join(", ")
                        };
                        let ttl_str = ttl.map(|t| format!(", TTL: {t}s")).unwrap_or_default();
                        let reply = Message::from_server(
                            &server_name,
                            "NOTICE",
                            vec![
                                &nick,
                                &format!(
                                    "✅ Spawned {child_nick} in {channel} (caps: {caps_str}{ttl_str})"
                                ),
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        tracing::info!(parent = %nick, child = %child_nick, channel = %channel, "AGENT SPAWN");
                    }

                    // AGENT GRANT   <nick|did> <capability> [ttl=<secs>]
                    // AGENT UNGRANT <nick|did> <capability>
                    //
                    // UNGRANT, not REVOKE: `AGENT REVOKE` already exists and
                    // means the governance kill-switch for a whole agent
                    // (PHASE-2, alongside PAUSE/RESUME). Withdrawing one
                    // capability is a different act and needs its own verb.
                    //
                    // The writer `agent_capability_grants` never had. Without it
                    // the table's TTLs, scopes and rate limits described grants
                    // that could not be made, and an agent could only ever hold
                    // what its own manifest claimed. Operator-only: conferring
                    // authority in a channel is a moderation act.
                    "GRANT" | "UNGRANT" => {
                        let granting = subcmd == "GRANT";
                        let (Some(target), Some(capability)) =
                            (msg.params.get(1), msg.params.get(2))
                        else {
                            let reply = Message::from_server(
                                &server_name,
                                irc::ERR_NEEDMOREPARAMS,
                                vec![
                                    &nick,
                                    "AGENT",
                                    "Usage: AGENT GRANT|UNGRANT <nick> <capability> [ttl=<secs>]",
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        };
                        // The channel the grant applies to: the one this session
                        // is in. Ambiguous with several, so require exactly one,
                        // matching how the other AGENT subcommands scope.
                        let joined: Vec<String> = {
                            let channels = state.channels.lock();
                            channels
                                .iter()
                                .filter(|(_, ch)| ch.members.contains(&session_id))
                                .map(|(name, _)| name.clone())
                                .collect()
                        };
                        let channel = match joined.first().cloned() {
                            Some(c) => c,
                            None => {
                                let reply = Message::from_server(
                                    &server_name,
                                    "NOTICE",
                                    vec![&nick, "AGENT GRANT: join a channel first"],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };

                        // Operator check, by DID so any of an op's devices works.
                        let granter_did = conn.authenticated_did.clone();
                        let is_op = {
                            let channels = state.channels.lock();
                            channels
                                .get(&channel)
                                .map(|ch| {
                                    ch.ops.contains(&session_id)
                                        || granter_did.as_ref().is_some_and(|d| {
                                            ch.founder_did.as_deref() == Some(d.as_str())
                                                || ch.did_ops.contains(d)
                                        })
                                })
                                .unwrap_or(false)
                        };
                        if !is_op {
                            let reply = Message::from_server(
                                &server_name,
                                irc::ERR_CHANOPRIVSNEEDED,
                                vec![&nick, &channel, "You're not channel operator"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        }

                        // Resolve the target to a DID: a nick if it is online,
                        // otherwise treat the argument as a DID directly.
                        let target_did = if target.starts_with("did:") {
                            Some(target.clone())
                        } else {
                            let sid = state
                                .nick_to_session
                                .lock()
                                .get_session(target)
                                .map(|s| s.to_string());
                            sid.and_then(|sid| state.session_dids.lock().get(&sid).cloned())
                        };
                        let Some(target_did) = target_did else {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![&nick, &format!("AGENT GRANT: no DID for {target}")],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            continue;
                        };

                        let mut ttl: u64 = 0;
                        for p in msg.params.iter().skip(3) {
                            if let Some(v) = p.strip_prefix("ttl=") {
                                ttl = v.parse().unwrap_or(0);
                            }
                        }

                        let granted_by = granter_did.unwrap_or_else(|| nick.clone());
                        let ok = if granting {
                            state
                                .with_db(|db| {
                                    db.grant_capability(
                                        &channel,
                                        &target_did,
                                        capability,
                                        None,
                                        ttl,
                                        false,
                                        0,
                                        &granted_by,
                                    )
                                    .map(|_| ())
                                })
                                .is_some()
                        } else {
                            state
                                .with_db(|db| {
                                    for g in db.get_capabilities(&channel, &target_did) {
                                        if &g.capability == capability {
                                            db.revoke_capability(g.id)?;
                                        }
                                    }
                                    Ok(())
                                })
                                .is_some()
                        };

                        let word = if granting { "Granted" } else { "Ungranted" };
                        let text = if ok {
                            format!("{word} {capability} for {target} in {channel}")
                        } else {
                            format!("AGENT {subcmd}: no database configured")
                        };
                        let reply =
                            Message::from_server(&server_name, "NOTICE", vec![&nick, &text]);
                        send(&state, &session_id, format!("{reply}\r\n"));
                        if ok {
                            tracing::info!(
                                channel = %channel, target = %target_did,
                                capability = %capability.as_str(), by = %granted_by, granting,
                                "Agent capability grant changed"
                            );
                        }
                    }

                    // AGENT DESPAWN <nick>
                    "DESPAWN" => {
                        let child_nick = match msg.params.get(1) {
                            Some(n) => n.clone(),
                            None => {
                                let reply = Message::from_server(
                                    &server_name,
                                    irc::ERR_NEEDMOREPARAMS,
                                    vec![&nick, "AGENT", "Usage: AGENT DESPAWN <nick>"],
                                );
                                send(&state, &session_id, format!("{reply}\r\n"));
                                continue;
                            }
                        };

                        // Find the spawned agent owned by this session
                        let removed = {
                            let mut spawned = state.spawned_agents.lock();
                            let found = spawned
                                .iter()
                                .find(|(_, sa)| {
                                    sa.nick.eq_ignore_ascii_case(&child_nick)
                                        && sa.parent_session == session_id
                                })
                                .map(|(k, v)| (k.clone(), v.clone()));
                            if let Some((key, _)) = &found {
                                spawned.remove(key);
                            }
                            found
                        };

                        if let Some((child_did, sa)) = removed {
                            let quit_line = format!(
                                ":{child_nick}!spawn@freeq/spawn QUIT :Despawned by {nick}\r\n"
                            );
                            helpers::broadcast_to_channel(&state, &sa.channel, &quit_line);
                            state.with_db(|db| db.record_despawn(&child_did));

                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![&nick, &format!("✅ Despawned {child_nick}")],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                            tracing::info!(parent = %nick, child = %child_nick, "AGENT DESPAWN");
                        } else {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![
                                    &nick,
                                    &format!("No spawned agent '{child_nick}' owned by you"),
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }

                    // AGENT MSG <child-nick> #channel :text — send message as spawned child
                    "MSG" => {
                        let (child_nick, target, text) =
                            match (msg.params.get(1), msg.params.get(2), msg.params.get(3)) {
                                (Some(cn), Some(t), Some(txt)) => {
                                    (cn.clone(), t.clone(), txt.clone())
                                }
                                _ => {
                                    let reply = Message::from_server(
                                        &server_name,
                                        irc::ERR_NEEDMOREPARAMS,
                                        vec![
                                            &nick,
                                            "AGENT",
                                            "Usage: AGENT MSG <child-nick> #channel :text",
                                        ],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                    continue;
                                }
                            };

                        // Verify child is owned by this session
                        let child_exists = state.spawned_agents.lock().values().any(|sa| {
                            sa.nick.eq_ignore_ascii_case(&child_nick)
                                && sa.parent_session == session_id
                        });

                        if child_exists {
                            let child_hostmask = format!("{child_nick}!spawn@freeq/spawn");
                            let msgid = crate::msgid::generate();
                            let line = format!(
                                "@msgid={msgid};+freeq.at/actor-class=agent;+freeq.at/parent={nick} :{child_hostmask} PRIVMSG {target} :{text}\r\n"
                            );
                            helpers::broadcast_to_channel(&state, &target, &line);
                        } else {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![
                                    &nick,
                                    &format!("No spawned agent '{child_nick}' owned by you"),
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }

                    _ => {
                        let reply = Message::from_server(
                            &server_name,
                            "NOTICE",
                            vec![
                                &nick,
                                &format!(
                                    "Unknown AGENT subcommand: {subcmd}. Use: REGISTER, PAUSE, RESUME, REVOKE, APPROVE, DENY, MANIFEST, SPAWN, DESPAWN, MSG"
                                ),
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    }
                }
            }

            // APPROVAL_REQUEST — agent requests approval for a capability.
            // Usage: APPROVAL_REQUEST #channel :capability;resource=description
            "APPROVAL_REQUEST" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                let channel = match msg.params.first() {
                    Some(c) if c.starts_with('#') => c.clone(),
                    _ => {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NEEDMOREPARAMS,
                            vec![
                                &nick,
                                "APPROVAL_REQUEST",
                                "Usage: APPROVAL_REQUEST #channel :capability;resource=desc",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        continue;
                    }
                };
                let raw_params = msg.params.get(1).cloned().unwrap_or_default();
                let mut capability = raw_params.as_str();
                let mut resource: Option<String> = None;
                if let Some((cap, rest)) = raw_params.split_once(';') {
                    capability = cap;
                    for part in rest.split(';') {
                        if let Some((k, v)) = part.split_once('=')
                            && k.trim() == "resource"
                        {
                            resource = Some(v.trim().to_string());
                        }
                    }
                }

                if let Some(ref did) = conn.authenticated_did {
                    let approval_id = crate::msgid::generate();
                    state.with_db(|db| {
                        db.create_approval(
                            &approval_id,
                            &channel,
                            did,
                            capability,
                            resource.as_deref(),
                        )
                    });

                    // Notify channel ops
                    let resource_str = resource
                        .as_deref()
                        .map(|r| format!(" on {r}"))
                        .unwrap_or_default();
                    let notice = format!(
                        ":{server_name} NOTICE {channel} :🔔 {nick} requests approval for '{capability}'{resource_str}. Use: AGENT APPROVE {nick} {capability}\r\n"
                    );
                    helpers::broadcast_to_channel(&state, &channel, &notice);

                    // Send structured TAGMSG for rich clients
                    let tagmsg = format!(
                        "@+freeq.at/event=approval_request;+freeq.at/approval-id={approval_id};+freeq.at/capability={} :{} TAGMSG {channel}\r\n",
                        irc::escape_tag_value(capability),
                        conn.hostmask()
                    );
                    helpers::broadcast_to_channel(&state, &channel, &tagmsg);

                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![
                            &nick,
                            &format!(
                                "Approval requested: {capability} in {channel} (id: {approval_id})"
                            ),
                        ],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    tracing::info!(nick = %nick, channel = %channel, capability = %capability, "Approval requested");
                } else {
                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![&nick, "Must be authenticated to request approval"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                }
            }

            // SPEND command — agent reports spend for budget tracking.
            // Usage: SPEND #channel :amount=0.03;unit=usd;desc=claude-sonnet-4-20250514: 1.2k tokens;task=01JQXYZ
            "SPEND" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                let channel = match msg.params.first() {
                    Some(c) if c.starts_with('#') => c.clone(),
                    _ => {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NEEDMOREPARAMS,
                            vec![
                                &nick,
                                "SPEND",
                                "Usage: SPEND #channel :amount=0.03;unit=usd;desc=...;task=...",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        continue;
                    }
                };
                let raw_params = msg.params.get(1).cloned().unwrap_or_default();
                let mut amount: f64 = 0.0;
                let mut unit = "usd".to_string();
                let mut description: Option<String> = None;
                let mut task_ref: Option<String> = None;
                for part in raw_params.split(';') {
                    if let Some((k, v)) = part.split_once('=') {
                        match k.trim() {
                            "amount" => amount = v.trim().parse().unwrap_or(0.0),
                            "unit" => unit = v.trim().to_string(),
                            "desc" | "description" => description = Some(v.trim().to_string()),
                            "task" => task_ref = Some(v.trim().to_string()),
                            _ => {}
                        }
                    }
                }

                if amount <= 0.0 {
                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![&nick, "SPEND requires positive amount"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }

                if let Some(ref did) = conn.authenticated_did {
                    // Record spend
                    state.with_db(|db| {
                        db.record_spend(
                            &channel,
                            did,
                            amount,
                            &unit,
                            description.as_deref(),
                            task_ref.as_deref(),
                        )
                    });

                    // Check budget and enforce.
                    //
                    // Inherited, not just own: a spawned agent holds a narrowed
                    // subset of its parent's authority, so the parent's limit
                    // applies to it. Otherwise a parent at its hard limit could
                    // spawn a child and keep spending.
                    let budget_json = state
                        .with_db(|db| Ok(db.get_budget_inherited(&channel, did)))
                        .flatten();
                    if let Some(ref bj) = budget_json
                        && let Ok(budget) =
                            serde_json::from_str::<crate::policy::types::BudgetPolicy>(bj)
                    {
                        let period_start = budget_period_start(&budget.period);
                        // Roll the delegated subtree up. Spend stays attributed
                        // to whoever spent it (the breakdown stays honest), but
                        // the limit question is about the whole subtree.
                        let budget_owner = state
                            .with_db(|db| Ok(db.budget_owner_for(&channel, did)))
                            .flatten()
                            .unwrap_or_else(|| did.clone());
                        let total_spent = state
                            .with_db(|db| {
                                Ok(db.sum_spend_with_descendants(
                                    &channel,
                                    &budget_owner,
                                    &budget.unit,
                                    period_start,
                                ))
                            })
                            .unwrap_or(0.0);
                        let ratio = total_spent / budget.max_amount;
                        let prev_ratio = (total_spent - amount) / budget.max_amount;

                        // Warn at threshold (first crossing)
                        if ratio >= budget.warn_threshold && prev_ratio < budget.warn_threshold {
                            let warn = format!(
                                ":{server_name} NOTICE {channel} :⚠ Budget {:.0}% used by {nick} ({:.2}/{:.2} {unit})\r\n",
                                ratio * 100.0,
                                total_spent,
                                budget.max_amount
                            );
                            helpers::broadcast_to_channel(&state, &channel, &warn);
                            // The sponsor is the one whose credits these are, and
                            // they are frequently not in the channel. `sponsor_did`
                            // is documented as "who gets notified and pays"; the
                            // notifying half lives here.
                            helpers::notify_sponsor(
                                &state,
                                &server_name,
                                &budget.sponsor_did,
                                &format!(
                                    "\u{26a0} Budget {:.0}% used by {nick} in {channel} ({:.2}/{:.2} {unit})",
                                    ratio * 100.0,
                                    total_spent,
                                    budget.max_amount
                                ),
                            );
                            tracing::info!(channel = %channel, agent = %nick, pct = ratio * 100.0, sponsor = %budget.sponsor_did, "Budget warning threshold hit");
                        }

                        // Block at limit
                        if ratio >= 1.0 && budget.hard_limit {
                            let block = format!(
                                ":{server_name} NOTICE {channel} :🛑 {nick} blocked: budget exceeded ({:.2}/{:.2} {unit})\r\n",
                                total_spent, budget.max_amount
                            );
                            helpers::broadcast_to_channel(&state, &channel, &block);
                            helpers::notify_sponsor(
                                &state,
                                &server_name,
                                &budget.sponsor_did,
                                &format!(
                                    "\u{1f6d1} {nick} blocked in {channel}: budget exceeded ({:.2}/{:.2} {unit})",
                                    total_spent, budget.max_amount
                                ),
                            );

                            // Send governance signal to agent
                            let gov_line = format!(
                                "@+freeq.at/governance=budget_exceeded;+freeq.at/spent={:.2};+freeq.at/limit={:.2};+freeq.at/unit={} :{server_name} TAGMSG {nick}\r\n",
                                total_spent,
                                budget.max_amount,
                                irc::escape_tag_value(&unit)
                            );
                            send(&state, &session_id, gov_line);
                        }
                    }

                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![&nick, &format!("💰 Recorded: {amount:.4} {unit}")],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                } else {
                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![&nick, "Must be authenticated to report spend"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                }
            }

            // BUDGET command — set or query channel budget.
            // Usage: BUDGET #channel — query
            // Usage: BUDGET #channel :max=50;unit=usd;period=per_day;sponsor=did:plc:xxx;warn=0.8;hard=true
            "BUDGET" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                let channel = match msg.params.first() {
                    Some(c) if c.starts_with('#') => c.clone(),
                    _ => {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NEEDMOREPARAMS,
                            vec![
                                &nick,
                                "BUDGET",
                                "Usage: BUDGET #channel [:max=50;unit=usd;period=per_day;...]",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        continue;
                    }
                };

                if let Some(raw) = msg.params.get(1) {
                    // Set budget — require op or oper
                    let is_op = {
                        let channels = state.channels.lock();
                        channels
                            .get(&channel.to_lowercase())
                            .map(|ch| ch.ops.contains(&session_id))
                            .unwrap_or(false)
                    };
                    if !is_op && !conn.is_oper {
                        let reply = Message::from_server(
                            &server_name,
                            "482",
                            vec![
                                &nick,
                                &channel,
                                "You must be a channel operator to set budgets",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                        continue;
                    }

                    let mut max_amount: f64 = 50.0;
                    let mut unit_str = "usd".to_string();
                    let mut period_str = "per_day".to_string();
                    let mut sponsor = conn
                        .authenticated_did
                        .clone()
                        .unwrap_or_else(|| nick.clone());
                    let mut warn: f64 = 0.8;
                    let mut hard = true;
                    for part in raw.split(';') {
                        if let Some((k, v)) = part.split_once('=') {
                            match k.trim() {
                                "max" | "max_amount" => {
                                    max_amount = v.trim().parse().unwrap_or(50.0)
                                }
                                "unit" => unit_str = v.trim().to_string(),
                                "period" => period_str = v.trim().to_string(),
                                "sponsor" => sponsor = v.trim().to_string(),
                                "warn" | "warn_threshold" => warn = v.trim().parse().unwrap_or(0.8),
                                "hard" | "hard_limit" => hard = v.trim() == "true",
                                _ => {}
                            }
                        }
                    }

                    let budget = crate::policy::types::BudgetPolicy {
                        unit: unit_str.clone(),
                        max_amount,
                        period: match period_str.as_str() {
                            "per_hour" => crate::policy::types::BudgetPeriod::PerHour,
                            "per_week" => crate::policy::types::BudgetPeriod::PerWeek,
                            "per_task" => crate::policy::types::BudgetPeriod::PerTask,
                            _ => crate::policy::types::BudgetPeriod::PerDay,
                        },
                        sponsor_did: sponsor,
                        warn_threshold: warn,
                        hard_limit: hard,
                        approval_threshold: None,
                    };
                    let budget_json = serde_json::to_string(&budget).unwrap_or_default();
                    let issuer = conn.authenticated_did.as_deref().unwrap_or(&nick);
                    state.with_db(|db| db.set_budget(&channel, None, &budget_json, issuer));

                    let reply = Message::from_server(
                        &server_name,
                        "NOTICE",
                        vec![
                            &nick,
                            &format!(
                                "💰 Budget set for {channel}: {max_amount:.2} {unit_str}/{period_str} (warn: {:.0}%, hard: {hard})",
                                warn * 100.0
                            ),
                        ],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));

                    // Broadcast to channel
                    let notice = format!(
                        ":{server_name} NOTICE {channel} :💰 Budget set: {max_amount:.2} {unit_str}/{period_str} by {nick}\r\n"
                    );
                    helpers::broadcast_to_channel(&state, &channel, &notice);
                    tracing::info!(channel = %channel, by = %nick, max = max_amount, unit = %unit_str, "BUDGET set");
                } else {
                    // Query budget
                    let budget_json = state
                        .with_db(|db| Ok(db.get_budget(&channel, None)))
                        .flatten();
                    if let Some(ref bj) = budget_json {
                        if let Ok(budget) =
                            serde_json::from_str::<crate::policy::types::BudgetPolicy>(bj)
                        {
                            let period_start = budget_period_start(&budget.period);
                            let total_spent = state
                                .with_db(|db| {
                                    Ok(db.sum_spend(&channel, None, &budget.unit, period_start))
                                })
                                .unwrap_or(0.0);
                            let remaining = budget.max_amount - total_spent;
                            let pct = (total_spent / budget.max_amount * 100.0).min(100.0);
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![
                                    &nick,
                                    &format!(
                                        "💰 {channel}: {total_spent:.2}/{:.2} {} ({pct:.0}% used, {remaining:.2} remaining)",
                                        budget.max_amount, budget.unit
                                    ),
                                ],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    } else {
                        let reply = Message::from_server(
                            &server_name,
                            "NOTICE",
                            vec![&nick, &format!("No budget set for {channel}")],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    }
                }
            }

            // PROVENANCE command — submit a provenance declaration for this agent.
            // Usage: PROVENANCE :<base64url-encoded JSON>
            "PROVENANCE" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                if msg.params.is_empty() {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![&nick, "PROVENANCE", "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                let encoded = &msg.params[0];
                // Try base64url decode, or accept raw JSON
                let json_result = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .or_else(|| serde_json::from_str::<serde_json::Value>(encoded).ok());

                match json_result {
                    Some(mut provenance) => {
                        if let Some(ref did) = conn.authenticated_did {
                            // Run synchronous verification. For FreeqBotDelegation/v1
                            // certs this checks the ed25519 sig against the creator's
                            // registered MSGSIG key (db.get_signing_key). Other shapes
                            // pass through as unverified.
                            //
                            // Hard-reject only on cert/session DID mismatch (the agent
                            // is presenting a cert that doesn't belong to its session).
                            let did_clone = did.clone();
                            let outcome_result = state
                                .with_db(|db| {
                                    Ok::<_, rusqlite::Error>(provenance::verify_provenance(
                                        &provenance,
                                        &did_clone,
                                        Some(db),
                                    ))
                                })
                                .unwrap_or_else(|| {
                                    // No DB attached — verify will report "no DB" reason.
                                    provenance::verify_provenance(&provenance, &did_clone, None)
                                });

                            match outcome_result {
                                Err(reject_reason) => {
                                    let reply = Message::from_server(
                                        &server_name,
                                        "NOTICE",
                                        vec![
                                            &nick,
                                            &format!("Provenance rejected: {reject_reason}"),
                                        ],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                    tracing::warn!(
                                        nick = %nick, did = %did, reason = %reject_reason,
                                        "Provenance declaration rejected"
                                    );
                                }
                                Ok(outcome) => {
                                    provenance::annotate(&mut provenance, &outcome);
                                    state
                                        .provenance_declarations
                                        .lock()
                                        .insert(did.clone(), provenance);
                                    let status = if outcome.verified {
                                        "verified"
                                    } else {
                                        "stored (unverified)"
                                    };
                                    let reply = Message::from_server(
                                        &server_name,
                                        "NOTICE",
                                        vec![
                                            &nick,
                                            &format!("Provenance {status}: {}", outcome.reason),
                                        ],
                                    );
                                    send(&state, &session_id, format!("{reply}\r\n"));
                                    tracing::info!(
                                        nick = %nick, did = %did,
                                        verified = outcome.verified,
                                        reason = %outcome.reason,
                                        "Provenance declaration stored"
                                    );
                                }
                            }
                        } else {
                            let reply = Message::from_server(
                                &server_name,
                                "NOTICE",
                                vec![&nick, "Must be authenticated to submit provenance"],
                            );
                            send(&state, &session_id, format!("{reply}\r\n"));
                        }
                    }
                    None => {
                        let reply = Message::from_server(
                            &server_name,
                            "NOTICE",
                            vec![
                                &nick,
                                "Invalid provenance format (expected base64url-encoded JSON or raw JSON)",
                            ],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    }
                }
            }

            // PRESENCE command — update structured agent presence.
            // Usage: PRESENCE :state=executing;status=building project;task=01JQXYZ
            "PRESENCE" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                if msg.params.is_empty() {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![&nick, "PRESENCE", "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                // Parse key=value pairs separated by semicolons
                let raw = &msg.params[0];
                let mut presence_state: Option<PresenceState> = None;
                let mut status_text: Option<String> = None;
                let mut task_ref: Option<String> = None;

                for part in raw.split(';') {
                    if let Some((k, v)) = part.split_once('=') {
                        match k.trim() {
                            "state" => presence_state = v.trim().parse().ok(),
                            "status" => status_text = Some(v.trim().to_string()),
                            "task" => task_ref = Some(v.trim().to_string()),
                            _ => {}
                        }
                    }
                }

                let ps = presence_state.unwrap_or(PresenceState::Online);
                let presence = AgentPresence {
                    state: ps,
                    status: status_text.clone(),
                    task: task_ref,
                    updated_at: chrono::Utc::now().timestamp(),
                };

                state
                    .agent_presence
                    .lock()
                    .insert(session_id.clone(), presence.clone());

                // Broadcast via AWAY mechanism for backwards compat
                let _away_json = serde_json::to_string(&presence).unwrap_or_default();
                let hostmask = conn.hostmask();

                // Set/clear AWAY state
                if ps == PresenceState::Online
                    || ps == PresenceState::Active
                    || ps == PresenceState::Idle
                {
                    state.session_away.lock().remove(&session_id);
                } else {
                    let away_text = status_text
                        .as_deref()
                        .unwrap_or(&ps.to_string())
                        .to_string();
                    state
                        .session_away
                        .lock()
                        .insert(session_id.clone(), away_text);
                }

                // Broadcast to away-notify subscribers in shared channels
                {
                    // Collect targets first, then send (avoid holding multiple locks)
                    let targets: Vec<String> = {
                        let channels = state.channels.lock();
                        let away_caps = state.cap_away_notify.lock();
                        let mut sids = Vec::new();
                        for ch in channels.values() {
                            if ch.members.contains(&session_id) {
                                for member_sid in &ch.members {
                                    if member_sid != &session_id && away_caps.contains(member_sid) {
                                        sids.push(member_sid.clone());
                                    }
                                }
                            }
                        }
                        sids
                    };
                    let conns = state.connections.lock();
                    // For active/online/idle: send AWAY with no parameter (= back from away)
                    // For other states: send human-readable AWAY text
                    let is_clear = ps == PresenceState::Online
                        || ps == PresenceState::Active
                        || ps == PresenceState::Idle;
                    let away_text = match (&status_text, ps) {
                        (Some(status), _) => format!("{ps}: {status}"),
                        (None, _) => ps.to_string(),
                    };
                    let line = if is_clear {
                        format!(":{hostmask} AWAY\r\n")
                    } else {
                        format!(":{hostmask} AWAY :{away_text}\r\n")
                    };
                    for sid in &targets {
                        if let Some(tx) = conns.get(sid) {
                            let _ = tx.try_send(line.clone());
                        }
                    }
                }

                let reply = Message::from_server(
                    &server_name,
                    "NOTICE",
                    vec![&nick, &format!("Presence updated: {ps}")],
                );
                send(&state, &session_id, format!("{reply}\r\n"));
                tracing::debug!(nick = %nick, state = %ps, "PRESENCE updated");
            }

            // HEARTBEAT command — agent liveness signal.
            // Usage: HEARTBEAT :state=active;ttl=60
            "HEARTBEAT" => {
                if !conn.registered {
                    continue;
                }
                let raw = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let mut hb_state = PresenceState::Active;
                let mut ttl: u64 = 60;

                for part in raw.split(';') {
                    if let Some((k, v)) = part.split_once('=') {
                        match k.trim() {
                            "state" => {
                                if let Ok(s) = v.trim().parse() {
                                    hb_state = s;
                                }
                            }
                            "ttl" => {
                                if let Ok(t) = v.trim().parse() {
                                    ttl = t;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let now = chrono::Utc::now().timestamp();
                state
                    .agent_heartbeats
                    .lock()
                    .insert(session_id.clone(), (now, ttl));

                // Update presence from heartbeat
                let presence = AgentPresence {
                    state: hb_state,
                    status: None,
                    task: None,
                    updated_at: now,
                };
                state
                    .agent_presence
                    .lock()
                    .insert(session_id.clone(), presence);
            }

            // Phase 4: Revoke a peer's S2S access (oper-only).
            // Usage: REVOKEPEER <endpoint_id>
            "REVOKEPEER" => {
                if !conn.registered {
                    continue;
                }
                let nick = conn.nick_or_star().to_string();
                if !conn.is_oper {
                    let reply = Message::from_server(
                        &server_name,
                        "481",
                        vec![&nick, "Permission Denied - You're not an IRC operator"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                if msg.params.is_empty() {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![&nick, "REVOKEPEER", "Not enough parameters"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                let target_peer = &msg.params[0];
                let manager = state.s2s_manager.lock().clone();
                if let Some(manager) = manager {
                    // Disconnect the peer
                    let removed = manager.peers.lock().await.remove(target_peer);
                    if removed.is_some() {
                        manager.peer_names.lock().await.remove(target_peer);
                        manager.authenticated_peers.lock().await.remove(target_peer);
                        manager.dedup.remove_peer(target_peer).await;
                        let notice = format!(
                            ":{} NOTICE {} :S2S peer {} revoked and disconnected\r\n",
                            server_name, nick, target_peer
                        );
                        send(&state, &session_id, notice);
                        tracing::warn!(
                            oper = %nick,
                            peer = %target_peer,
                            "S2S peer revoked via REVOKEPEER"
                        );
                    } else {
                        let notice = format!(
                            ":{} NOTICE {} :S2S peer {} not found in active connections\r\n",
                            server_name, nick, target_peer
                        );
                        send(&state, &session_id, notice);
                    }
                } else {
                    let notice = format!(":{} NOTICE {} :S2S not active\r\n", server_name, nick);
                    send(&state, &session_id, notice);
                }
            }
            "QUIT" => {
                break;
            }
            _ => {
                if conn.registered {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_UNKNOWNCOMMAND,
                        vec![conn.nick_or_star(), &msg.command, "Unknown command"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                }
            }
        }
    }

    // Check if this DID has other active sessions (multi-device)
    let did = conn.authenticated_did.as_deref();
    let is_last_session_for_did = if let Some(d) = did {
        let mut ds = state.did_sessions.lock();
        if let Some(sessions) = ds.get_mut(d) {
            sessions.remove(&session_id);
            let remaining = sessions.len();
            if sessions.is_empty() {
                ds.remove(d);
            }
            remaining == 0
        } else {
            true
        }
    } else {
        true // Guest sessions are always "last"
    };

    // Clean up AV sessions: leave only THIS connection's instance slots —
    // not every slot for the DID (the user may have other tabs/devices in
    // the same call). When the user wasn't using per-instance tags (older
    // clients), fall back to the legacy whole-DID cleanup.
    {
        let did_for_av = conn
            .authenticated_did
            .clone()
            .unwrap_or_else(|| format!("guest:{}", conn.nick.as_deref().unwrap_or("*")));

        let instances: Vec<String> = state
            .av_instances_per_conn
            .lock()
            .remove(&session_id)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();

        // A DID user's *last* connection gets an AV grace window so a brief
        // network blip + reconnect doesn't end their call. Guests, multi-device
        // users (another live session remains), and legacy clients with no
        // per-instance bookkeeping tear down immediately.
        let defer = crate::av::av_disconnect_deferred(
            conn.authenticated_did.is_some(),
            is_last_session_for_did,
        ) && !instances.is_empty();

        if defer {
            // Grace period for AV, aligned with the channel-membership grace.
            const AV_GRACE_SECS: u64 = QUIT_GRACE_SECS;
            tracing::info!(
                did = %did_for_av, instances = instances.len(),
                "AV: deferring teardown ({}s grace for blip/reconnect)", AV_GRACE_SECS
            );
            // Mark these instances as grace-pending so the join-time orphan
            // reaper leaves their roster slots alone until the grace decides.
            {
                let mut pending = state.av_grace_pending.lock();
                for inst in &instances {
                    pending.insert(inst.clone());
                }
            }
            let state2 = state.clone();
            let did2 = did_for_av.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(AV_GRACE_SECS)).await;
                {
                    let mut pending = state2.av_grace_pending.lock();
                    for inst in &instances {
                        pending.remove(inst);
                    }
                }
                for inst in &instances {
                    // If the instance reappeared on any live connection, the
                    // user reconnected and rejoined — keep the slot untouched.
                    // Otherwise tear it down exactly like the immediate path.
                    // This self-heals: a reconnect that does NOT rejoin the
                    // call still gets its stale slot cleaned up here.
                    if crate::av::instance_claimed_by_live_conn(
                        &state2.av_instances_per_conn.lock(),
                        inst,
                    ) {
                        tracing::info!(instance = %inst, did = %did2, "AV: grace — rejoined, call kept");
                        continue;
                    }
                    let left: Vec<(String, Option<String>, String, bool)> = {
                        let mut mgr = state2.av_sessions.lock();
                        mgr.leave_for_did_instance(&did2, Some(inst))
                    };
                    for (av_sid, channel, av_nick, should_end) in &left {
                        finish_av_slot_teardown(
                            &state2,
                            av_sid,
                            channel,
                            av_nick,
                            *should_end,
                            inst,
                        );
                    }
                    if !left.is_empty() {
                        tracing::info!(instance = %inst, did = %did2, "AV: grace expired — not rejoined, torn down");
                    }
                }
            });
        } else {
            // Immediate teardown. Each entry carries the per-device instance so
            // the `left` signal names the exact device that dropped — clients
            // key teardown on the instance (matches the media path), not nick.
            let left_sessions: Vec<AvLeftSession> = {
                let mut mgr = state.av_sessions.lock();
                if instances.is_empty() {
                    // Legacy path — no per-instance bookkeeping for this
                    // connection, so mark all DID slots left.
                    mgr.leave_all_for_did(&did_for_av)
                        .into_iter()
                        .map(|(sid, ch, nick, end)| (sid, ch, nick, end, None))
                        .collect()
                } else {
                    let mut out = Vec::new();
                    for inst in &instances {
                        for (sid, ch, nick, end) in
                            mgr.leave_for_did_instance(&did_for_av, Some(inst))
                        {
                            out.push((sid, ch, nick, end, Some(inst.clone())));
                        }
                    }
                    out
                }
            };

            for (av_sid, channel, av_nick, should_end, instance) in &left_sessions {
                finish_av_slot_teardown(
                    &state,
                    av_sid,
                    channel,
                    av_nick,
                    *should_end,
                    instance.as_deref().unwrap_or(""),
                );
            }
        }
    }

    // Grace period for DID users: hold channel membership for 30s before broadcasting QUIT.
    // If they reconnect within that window, suppress the quit/join churn entirely.
    const QUIT_GRACE_SECS: u64 = 30;

    if let Some(ref nick) = conn.nick {
        if is_last_session_for_did {
            if let Some(ref did) = conn.authenticated_did {
                // DID user — enter ghost mode instead of immediate QUIT
                let hostmask = conn.hostmask();

                // Collect channel membership to preserve.
                //
                // Cross-reference with user_channels DB: PART removes from user_channels,
                // so only channels still in user_channels are candidates for ghost restore.
                // This prevents ghost sessions from silently re-joining channels the user
                // explicitly PARTed before disconnecting — PART is authoritative.
                //
                // When there is no DB, fall back to in-memory membership (old behaviour).
                let subscribed: std::collections::HashSet<String> = state
                    .with_db(|db| db.get_user_channels(did))
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let ghost_channels: Vec<(String, bool, bool, bool)> = {
                    let channels = state.channels.lock();
                    channels
                        .iter()
                        .filter(|(name, ch)| {
                            ch.members.contains(&session_id)
                                && (state.db.is_none() || subscribed.contains(name.as_str()))
                        })
                        .map(|(name, ch)| {
                            (
                                name.clone(),
                                ch.ops.contains(&session_id),
                                ch.voiced.contains(&session_id),
                                ch.halfops.contains(&session_id),
                            )
                        })
                        .collect()
                };

                let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

                // Remove from channels/state now, but hold nick and don't broadcast
                cleanup_session_state(&state, &session_id);

                // Don't remove the nick — ghost holds it
                // state.nick_to_session.lock().remove_by_nick(nick); // <-- NOT here

                let ghost = crate::server::GhostSession {
                    nick: nick.clone(),
                    hostmask: hostmask.clone(),
                    session_id: session_id.clone(),
                    channels: ghost_channels,
                    disconnect_time: std::time::Instant::now(),
                    cancel: cancel_tx,
                };
                state.ghost_sessions.lock().insert(did.clone(), ghost);

                tracing::info!(
                    %session_id, nick = %nick, did = %did,
                    "Entered ghost mode ({}s grace period)", QUIT_GRACE_SECS
                );

                // Spawn deferred QUIT broadcast
                let state_clone = state.clone();
                let did_clone = did.clone();
                let nick_clone = nick.clone();
                let hostmask_clone = hostmask.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(QUIT_GRACE_SECS)) => {
                            // Grace period expired — broadcast QUIT now
                            let ghost = state_clone.ghost_sessions.lock().remove(&did_clone);
                            if let Some(ghost) = ghost {
                                let quit_msg = format!(":{hostmask_clone} QUIT :Connection closed\r\n");
                                let channels = state_clone.channels.lock();
                                let conns = state_clone.connections.lock();
                                for ch in channels.values() {
                                    for member in &ch.members {
                                        if let Some(tx) = conns.get(member) {
                                            let _ = tx.try_send(quit_msg.clone());
                                        }
                                    }
                                }
                                drop(conns);
                                drop(channels);
                                // Remove only THIS (ghost) session's nick binding, not every
                                // session sharing the nick. remove_by_nick wipes the sid→nick
                                // reverse mapping for ALL sessions with this nick, so if the
                                // user reconnected another device during the grace window, that
                                // live device would keep its channel membership but vanish from
                                // NAMES (can chat, invisible in the member list). remove_by_session
                                // removes just the ghost and promotes a live sibling as primary.
                                state_clone
                                    .nick_to_session
                                    .lock()
                                    .remove_by_session(&ghost.session_id);
                                // Evict the ghost's stale session_id from ch.members.
                                // cleanup_session_state (called at disconnect) intentionally
                                // skips cleanup_channel_membership to preserve ghost membership
                                // during the grace window. Now that grace has expired, clean up
                                // to prevent the old session_id from being a ghost member forever.
                                cleanup_channel_membership(&state_clone, &ghost.session_id);
                                tracing::info!(
                                    nick = %nick_clone, did = %did_clone,
                                    "Ghost grace expired — broadcasting QUIT"
                                );
                                // S2S
                                let origin = state_clone.server_iroh_id.lock().clone().unwrap_or_default();
                                s2s_broadcast(&state_clone, crate::s2s::S2sMessage::Quit {
                                    event_id: s2s_next_event_id(&state_clone),
                                    nick: nick_clone,
                                    reason: "Connection closed".to_string(),
                                    origin,
                                });
                            }
                        }
                        _ = cancel_rx => {
                            // Reconnected — ghost was reclaimed by attach_same_did.
                            // Stale session_id was already cleaned up from ch.members
                            // and nick_to_session during reclaim. No QUIT needed.
                        }
                    }
                });
            } else {
                // Guest user — immediate QUIT (no grace period)
                let hostmask = conn.hostmask();
                broadcast_quit(&state, &session_id, &hostmask);
                // Remove only this session (multi-device safe — see the ghost path).
                state.nick_to_session.lock().remove_by_session(&session_id);
                broadcast_quit_s2s(&state, nick);
                cleanup_session_state(&state, &session_id);
                cleanup_channel_membership(&state, &session_id);
            }
        } else {
            tracing::info!(
                %session_id,
                nick = %nick,
                "Session closed but other sessions remain for DID"
            );
            cleanup_session_state(&state, &session_id);
            cleanup_channel_membership(&state, &session_id);
            // Drop this session_id from the NickMap. If it was the primary
            // for the nick, NickMap.remove_by_session promotes a sibling
            // session that still holds the nick. Without this, the nick→sid
            // pointer can be left dangling at a dead session_id, breaking
            // WHOIS/PRIVMSG routing for the still-online sibling.
            state.nick_to_session.lock().remove_by_session(&session_id);
        }
    } else {
        cleanup_session_state(&state, &session_id);
        cleanup_channel_membership(&state, &session_id);
    }

    tracing::info!(
        %session_id,
        nick = conn.nick.as_deref().unwrap_or("-"),
        did = conn.authenticated_did.as_deref().unwrap_or("-"),
        last_session = is_last_session_for_did,
        "Connection closed"
    );

    write_handle.abort();
    Ok(())
}

/// Constant-time byte comparison to prevent timing side-channel attacks (M-16).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Detect the client software from the USER realname field.
fn detect_client(realname: &str) -> String {
    let r = realname.to_lowercase();
    if r.contains("freeq web") {
        return "freeq-web".to_string();
    }
    if r.contains("freeq ios") {
        return "freeq-ios".to_string();
    }
    if r.contains("freeq android") {
        return "freeq-android".to_string();
    }
    if r == "freeq" {
        return "freeq-sdk".to_string();
    }
    // Common IRC clients
    if r.contains("irssi") {
        return "irssi".to_string();
    }
    if r.contains("weechat") {
        return "weechat".to_string();
    }
    if r.contains("hexchat") {
        return "hexchat".to_string();
    }
    if r.contains("thunderbird") {
        return "thunderbird".to_string();
    }
    if r.contains("textual") {
        return "textual".to_string();
    }
    if r.contains("mutter") {
        return "mutter".to_string();
    }
    if r.contains("irccloud") {
        return "irccloud".to_string();
    }
    if r.contains("znc") {
        return "znc".to_string();
    }
    if r.contains("kiwi") {
        return "kiwi-irc".to_string();
    }
    if r.contains("thelounge") {
        return "thelounge".to_string();
    }
    if r.contains("revolution") {
        return "revolution-irc".to_string();
    }
    if r.contains("goguma") {
        return "goguma".to_string();
    }
    // fallback: first word of realname, capped
    let first = realname.split_whitespace().next().unwrap_or("unknown");
    first.chars().take(20).collect()
}

/// Broadcast QUIT to all channels the session is in.
fn broadcast_quit(state: &Arc<SharedState>, session_id: &str, hostmask: &str) {
    let quit_msg = format!(":{hostmask} QUIT :Connection closed\r\n");
    let channels = state.channels.lock();
    let conns = state.connections.lock();
    for ch in channels.values() {
        if ch.members.contains(session_id) {
            for member in &ch.members {
                if member != session_id
                    && let Some(tx) = conns.get(member)
                {
                    let _ = tx.try_send(quit_msg.clone());
                }
            }
        }
    }
}

/// Broadcast QUIT to S2S peers.
fn broadcast_quit_s2s(state: &Arc<SharedState>, nick: &str) {
    let origin = state.server_iroh_id.lock().clone().unwrap_or_default();
    s2s_broadcast(
        state,
        crate::s2s::S2sMessage::Quit {
            event_id: s2s_next_event_id(state),
            nick: nick.to_string(),
            reason: "Connection closed".to_string(),
            origin,
        },
    );
}

/// Clean up per-session state (connections, caps, etc.) but NOT channel membership.
fn cleanup_session_state(state: &Arc<SharedState>, session_id: &str) {
    state.connections.lock().remove(session_id);
    state.session_kill.lock().remove(session_id);
    state.liveness_probes.lock().remove(session_id);
    state.session_dids.lock().remove(session_id);
    state.session_handles.lock().remove(session_id);
    state.session_iroh_ids.lock().remove(session_id);
    state.session_away.lock().remove(session_id);
    state.msg_timestamps.lock().remove(session_id);
    state.session_msg_keys.lock().remove(session_id);
    state.session_client_info.lock().remove(session_id);
    state.cap_message_tags.lock().remove(session_id);
    state.cap_multi_prefix.lock().remove(session_id);
    state.cap_echo_message.lock().remove(session_id);
    state.cap_server_time.lock().remove(session_id);
    state.cap_batch.lock().remove(session_id);
    state.cap_draft_multiline.lock().remove(session_id);
    // Drop any open BATCH state for this session — the client is gone,
    // those batches will never be closed.
    state
        .open_batches
        .lock()
        .retain(|(sid, _bid), _| sid != session_id);
    state.cap_account_notify.lock().remove(session_id);
    state.cap_extended_join.lock().remove(session_id);
    state.cap_away_notify.lock().remove(session_id);
    state.cap_act.lock().remove(session_id);
    state.cap_account_tag.lock().remove(session_id);
    state.cap_read_marker.lock().remove(session_id);
    state.session_read_markers.lock().remove(session_id);
    state.server_opers.lock().remove(session_id);
    state.session_actor_class.lock().remove(session_id);
    state.agent_presence.lock().remove(session_id);
    state.agent_heartbeats.lock().remove(session_id);

    // Clean up any spawned (virtual) child agents owned by this session
    let mut spawned = state.spawned_agents.lock();
    let children: Vec<crate::server::SpawnedAgent> = spawned
        .values()
        .filter(|sa| sa.parent_session == session_id)
        .cloned()
        .collect();
    for child in &children {
        spawned.remove(&child.child_did);
    }
    drop(spawned);

    // Broadcast QUIT for each orphaned child
    for child in children {
        let quit_line = format!(
            ":{}!spawn@freeq/spawn QUIT :Parent disconnected\r\n",
            child.nick
        );
        helpers::broadcast_to_channel(state, &child.channel, &quit_line);
        state.with_db(|db| db.record_despawn(&child.child_did));
        tracing::info!(child = %child.nick, parent_session = %session_id, "Despawned orphaned child agent");
    }
}

/// Remove a session from all channels. Retains channels that still have content.
fn cleanup_channel_membership(state: &Arc<SharedState>, session_id: &str) {
    let mut channels = state.channels.lock();
    for ch in channels.values_mut() {
        ch.members.remove(session_id);
        ch.ops.remove(session_id);
        ch.voiced.remove(session_id);
        ch.halfops.remove(session_id);
    }
    channels.retain(|_, ch| {
        !ch.members.is_empty()
            || !ch.remote_members.is_empty()
            || ch.founder_did.is_some()
            || ch.topic.is_some()
            || !ch.bans.is_empty()
    });
}

/// Compute the start timestamp for a budget period.
pub fn budget_period_start(period: &crate::policy::types::BudgetPeriod) -> i64 {
    use crate::policy::types::BudgetPeriod;
    let now = chrono::Utc::now();
    match period {
        BudgetPeriod::PerHour => now
            .date_naive()
            .and_hms_opt(now.time().hour(), 0, 0)
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0),
        BudgetPeriod::PerDay => now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0),
        BudgetPeriod::PerWeek => {
            use chrono::Datelike;
            let days_since_monday = now.weekday().num_days_from_monday();
            let monday = now.date_naive() - chrono::Duration::days(days_since_monday as i64);
            monday
                .and_hms_opt(0, 0, 0)
                .map(|dt| dt.and_utc().timestamp())
                .unwrap_or(0)
        }
        BudgetPeriod::PerTask => 0, // per-task tracks from task creation, not calendar
    }
}

use chrono::Timelike;
