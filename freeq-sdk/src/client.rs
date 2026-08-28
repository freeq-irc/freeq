//! IRC client with ATPROTO-CHALLENGE SASL support.
//!
//! This is the main entry point for SDK consumers. It manages the TCP
//! connection, IRC registration, CAP/SASL negotiation, and emits events.
//! Supports both plaintext and TLS connections.
//!
//! ## SASL Authentication
//!
//! Two SASL methods are supported:
//!
//! - **`web-token`**: A short-lived token minted by the auth broker after OAuth.
//!   Set `config.sasl_token` and `config.sasl_method = "web-token"`. The token is
//!   sent as the SASL payload and verified against the server's in-memory token map.
//!   Tokens expire after 5 minutes. Best for web and mobile clients that go through
//!   the OAuth broker flow.
//!
//! - **`crypto`**: Direct cryptographic challenge-response using the user's AT Protocol
//!   signing key. Set `config.sasl_method = "crypto"` and provide a DID + signing key.
//!   The server sends a challenge; the client signs it; the server verifies against the
//!   DID document. Best for bots and CLI tools with direct key access.
//!
//! ## Reconnection
//!
//! The SDK does not implement automatic reconnection. Consumers should implement
//! their own reconnect logic with exponential backoff (e.g., 2→4→8→16→30s cap)
//! to avoid overwhelming the server. Listen for [`Event::Disconnected`] and retry.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;

use crate::auth::{self, ChallengeSigner};
use crate::event::Event;
use crate::irc::Message;

/// Registry for pending echo-message callbacks.
/// When a client sends a PRIVMSG with a `+freeq.at/echo-nonce` tag, the nonce
/// is registered here. When the echo comes back, the msgid is sent via the oneshot.
type EchoRegistry =
    std::sync::Arc<parking_lot::Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>>;

/// Configuration for connecting to an IRC server.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Server address (host:port).
    pub server_addr: String,
    /// Desired nickname.
    pub nick: String,
    /// Username (ident).
    pub user: String,
    /// Real name.
    pub realname: String,
    /// Use TLS.
    pub tls: bool,
    /// Skip TLS certificate verification (for self-signed certs).
    pub tls_insecure: bool,
    /// One-time web-token for SASL WEB-TOKEN authentication (from OAuth flow).
    pub web_token: Option<String>,
    /// WebSocket URL — `wss://host/path` or `ws://host/path`. When set, the
    /// SDK connects via WebSocket instead of raw TCP. Mirrors the JS
    /// client's transport (`freeq-sdk-js/src/transport.ts`) so iOS can
    /// reach the server on networks that block port 6667.
    pub websocket_url: Option<String>,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:6667".to_string(),
            nick: "user".to_string(),
            user: "user".to_string(),
            realname: "IRC AT SDK User".to_string(),
            tls: false,
            tls_insecure: false,
            web_token: None,
            websocket_url: None,
        }
    }
}

impl ConnectConfig {
    /// Validate configuration fields. Returns an error describing the first invalid field.
    pub fn validate(&self) -> Result<(), String> {
        if self.server_addr.is_empty() {
            return Err("server_addr must not be empty".into());
        }
        if self.nick.is_empty() || self.nick.len() > 64 {
            return Err("nick must be 1-64 characters".into());
        }
        if self.nick.contains(|c: char| {
            c.is_control()
                || c == ' '
                || c == ','
                || c == '*'
                || c == '?'
                || c == '!'
                || c == '@'
                || c == '#'
        }) {
            return Err("nick contains invalid characters".into());
        }
        if self.user.is_empty() {
            return Err("user must not be empty".into());
        }
        if self.tls_insecure && !self.tls {
            tracing::warn!("tls_insecure has no effect when tls is false");
        }
        Ok(())
    }
}

/// Commands the consumer can send to the client.
#[derive(Debug)]
pub enum Command {
    Join(String),
    /// A PRIVMSG, with any client tags the caller wants on it. The tags are
    /// part of what gets signed (the ones the chat document covers), so they
    /// travel with the command rather than being pre-formatted into a `Raw`
    /// line — a signature cannot cover bytes the signer never sees.
    Privmsg {
        target: String,
        text: String,
        tags: std::collections::HashMap<String, String>,
    },
    /// Send a `draft/multiline` BATCH. Used when the assembled body
    /// either contains `\n` (one chunk per logical line, concat=false)
    /// or exceeds a single line and needs ciphertext-style chunking
    /// (concat=true on every chunk after the first). Opener tags ride
    /// on the BATCH opener; the SDK reuses the consumer-supplied chunks
    /// verbatim — no internal line-splitting — so the wire shape is
    /// fully controlled by the caller.
    SendMultiline {
        target: String,
        chunks: Vec<MultilineChunk>,
        opener_tags: std::collections::HashMap<String, String>,
    },
    /// A TAGMSG — tags, no body. Structured for the same reason `Privmsg` is:
    /// a delete or a reaction *is* its tags, so the signer has to see them
    /// before they reach the wire. Ephemera (typing, AV signalling) travel as
    /// TAGMSGs too and are deliberately left unsigned.
    Tagmsg {
        target: String,
        tags: std::collections::HashMap<String, String>,
    },
    /// A coordination event: the TAGMSG a task event is stored as, and the
    /// companion message that renders it.
    ///
    /// Structured, and one command for the pair, because the two halves are
    /// two documents that have to agree: the TAGMSG signs the coordination
    /// document over `event_id`, and the message signs itself with the same
    /// coordination tags inside it. `event_id` arrives already minted — the
    /// caller was handed it before this reached the wire, and the signature
    /// covers exactly that id.
    CoordinationEvent {
        channel: String,
        event_id: String,
        event_type: String,
        /// The wire value of `+freeq.at/payload`, already percent-encoded.
        payload: String,
        ref_id: Option<String>,
        /// The kind of evidence an `evidence_attach` carries. Rides as
        /// `+freeq.at/evidence-type` and is covered by both signatures.
        evidence_type: Option<String>,
        human_text: String,
    },
    /// A task event: the signed TAGMSG that *is* the event, and the companion
    /// line that renders it for the people in the room.
    ///
    /// Structured, and one command for the pair, because the two halves are
    /// two documents that have to agree. `event_id` arrives already minted —
    /// the caller was handed it before this reached the wire, and the
    /// signature covers exactly that id. `done` carries back the one answer a
    /// caller must not miss: a task event is never sent unsigned, so a session
    /// that cannot sign is an error rather than a quieter send.
    Act {
        target: String,
        event_id: String,
        tags: std::collections::HashMap<String, String>,
        human_text: String,
        done: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Raw(String),
    Quit(Option<String>),
}

/// One chunk of a `draft/multiline` send. `concat=true` translates to
/// `draft/multiline-concat` on the wire — receivers join with no
/// separator. The first chunk's `concat` is conventionally `false`.
#[derive(Debug, Clone)]
pub struct MultilineChunk {
    pub body: String,
    pub concat: bool,
}

/// Per-PRIVMSG byte budget for a multiline chunk. Kept safely under the wire
/// line cap (matches the JS SDK). A source line longer than this is split into
/// `concat` continuation chunks.
const MULTILINE_PER_CHUNK_BYTES: usize = 6400;
/// Per-BATCH ceilings (freeq server's advertised `draft/multiline` policy). A
/// send exceeding either is split across SEVERAL batches (several logical
/// messages) rather than one oversized batch the server would reject.
const MULTILINE_MAX_LINES: usize = 100;
const MULTILINE_MAX_BYTES: usize = 40000;

/// Split `text` into `draft/multiline` chunks so the assembled body is
/// byte-identical to the input. Source lines (`\n`-separated) open a new chunk
/// with `concat=false`; a line longer than `budget` bytes is hard-split into
/// `concat=true` continuation chunks (rejoined with no separator). An empty
/// source line emits an empty non-concat chunk so blank lines survive.
/// Splits only on UTF-8 char boundaries.
fn chunk_multiline_body(text: &str, budget: usize) -> Vec<MultilineChunk> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            out.push(MultilineChunk {
                body: String::new(),
                concat: false,
            });
            continue;
        }
        let mut first = true;
        let mut start = 0;
        while start < line.len() {
            let mut end = (start + budget).min(line.len());
            while end > start && !line.is_char_boundary(end) {
                end -= 1;
            }
            // A single char wider than the budget: take at least that char.
            if end == start {
                end = start + 1;
                while end < line.len() && !line.is_char_boundary(end) {
                    end += 1;
                }
            }
            out.push(MultilineChunk {
                body: line[start..end].to_string(),
                concat: !first,
            });
            first = false;
            start = end;
        }
    }
    out
}

/// Group chunks into batches that each stay within the server's per-batch
/// `max-lines` / `max-bytes` policy. A batch boundary is only taken at a
/// non-`concat` chunk, so a hard-split line is never severed across batches.
fn group_chunks_into_batches(
    chunks: Vec<MultilineChunk>,
    max_lines: usize,
    max_bytes: usize,
) -> Vec<Vec<MultilineChunk>> {
    let mut groups: Vec<Vec<MultilineChunk>> = Vec::new();
    let mut cur: Vec<MultilineChunk> = Vec::new();
    let mut cur_len = 0usize;
    for c in chunks {
        let sep = if !cur.is_empty() && !c.concat { 1 } else { 0 };
        let starts_new = !cur.is_empty()
            && !c.concat
            && (cur.len() + 1 > max_lines || cur_len + sep + c.body.len() > max_bytes);
        if starts_new {
            groups.push(std::mem::take(&mut cur));
            cur_len = 0;
        }
        cur_len += (if !cur.is_empty() && !c.concat { 1 } else { 0 }) + c.body.len();
        cur.push(c);
    }
    if !cur.is_empty() {
        groups.push(cur);
    }
    groups
}

/// State for one in-flight inbound `draft/multiline` batch — the
/// opener-derived metadata plus the accumulated chunks. Cleared when
/// the BATCH closer fires.
#[derive(Debug)]
struct InboundMultilineBatch {
    target: String,
    from: String,
    opener_tags: std::collections::HashMap<String, String>,
    lines: Vec<MultilineChunk>,
    parent_batch_id: Option<String>,
}

/// Negotiated capability state, shared between the read loop (which
/// populates it from CAP LS/ACK) and the `ClientHandle` (which reads it
/// to decide e.g. whether a `\n`-bearing `privmsg` should auto-route
/// to a `draft/multiline` BATCH, and how big a batch may be).
#[derive(Default)]
pub(crate) struct CapsState {
    /// Cap names the server ACKed.
    acked: HashSet<String>,
    /// Server-advertised `draft/multiline` `(max_bytes, max_lines)`, parsed
    /// from the CAP LS value. `None` until an LS line carries params, in which
    /// case sends fall back to the built-in `MULTILINE_MAX_*` defaults.
    multiline_policy: Option<(usize, usize)>,
}
pub(crate) type CapsAcked = Arc<parking_lot::Mutex<CapsState>>;

/// Session-learned nick↔DID bindings, shared between the read loop (which
/// learns them) and `ClientHandle` (which resolves send targets through
/// them). The two directions deliberately have different lifetimes:
///
/// - `nick_to_did` is addressing-grade: cleared when the nick's owner quits,
///   because a released nick can be recycled by someone else and routing
///   must never follow a stale binding.
/// - `did_to_nick` is display/keying-grade and retained: a DID is permanent,
///   and a DM thread must keep its key (and name) after the peer goes
///   offline. A rename overwrites it on the next join/whois/message.
#[derive(Default)]
pub(crate) struct DidMapsState {
    /// lowercase nick → DID. Addressing-grade; cleared on QUIT.
    nick_to_did: HashMap<String, String>,
    /// DID → lowercase nick. Display/keying-grade; survives QUIT.
    did_to_nick: HashMap<String, String>,
}

impl DidMapsState {
    /// Learn an authoritative binding (extended-join, WHOIS 330, account
    /// tag). Returns true when new/changed — the caller emits
    /// [`Event::MemberDid`] exactly then.
    fn learn(&mut self, nick: &str, did: &str) -> bool {
        let lc = nick.to_lowercase();
        let is_new = self.nick_to_did.get(&lc).map(|d| d.as_str()) != Some(did);
        self.nick_to_did.insert(lc.clone(), did.to_string());
        self.did_to_nick.insert(did.to_string(), lc);
        is_new
    }

    /// Learn the display direction only (CHATHISTORY TARGETS): the display
    /// nick may be historical, so it must not become an addressing binding.
    fn learn_display(&mut self, did: &str, nick: &str) {
        self.did_to_nick
            .insert(did.to_string(), nick.to_lowercase());
    }

    /// The peer's DID whose retained display nick is `nick`, if any.
    fn reverse_did_for_nick(&self, nick: &str) -> Option<String> {
        let lc = nick.to_lowercase();
        self.did_to_nick
            .iter()
            .find(|(_, n)| **n == lc)
            .map(|(d, _)| d.clone())
    }

    /// DM buffer/thread key: loose resolution (addressing map, then the
    /// retained display binding) so an offline peer's thread keeps one key.
    fn dm_key(&self, peer: &str) -> String {
        crate::address::dm_peer_key(peer, |n| {
            self.nick_to_did
                .get(&n.to_lowercase())
                .cloned()
                .or_else(|| self.reverse_did_for_nick(n))
        })
    }

    /// Wire target: strict resolution (addressing map only) — routing never
    /// rides a display binding.
    fn wire_target(&self, peer: &str) -> String {
        crate::address::dm_peer_key(peer, |n| self.nick_to_did.get(&n.to_lowercase()).cloned())
    }

    /// A nick's owner quit: forget the addressing binding (the nick can be
    /// recycled) but keep the display binding (the DID is permanent).
    fn forget_nick(&mut self, nick: &str) {
        self.nick_to_did.remove(&nick.to_lowercase());
    }

    /// A user renamed: move their addressing binding to the new nick and
    /// refresh the display binding.
    fn rename(&mut self, old_nick: &str, new_nick: &str) {
        if let Some(did) = self.nick_to_did.remove(&old_nick.to_lowercase()) {
            self.learn(new_nick, &did);
        }
    }
}

pub(crate) type DidMaps = Arc<parking_lot::Mutex<DidMapsState>>;

/// Compute the DM key for an inbound/echoed message, or `None` for channels.
/// The peer is the non-self end: our echo's peer is the target, an incoming
/// message's peer is the sender.
fn dm_key_for(maps: &DidMaps, own_nick: &str, from: &str, target: &str) -> Option<String> {
    if target.starts_with('#') || target.starts_with('&') {
        return None;
    }
    let peer = if from.eq_ignore_ascii_case(own_nick) {
        target
    } else {
        from
    };
    Some(maps.lock().dm_key(peer))
}

/// A handle to a running IRC client connection.
#[derive(Clone)]
pub struct ClientHandle {
    cmd_tx: mpsc::Sender<Command>,
    echo_registry: EchoRegistry,
    caps_acked: CapsAcked,
    did_maps: DidMaps,
}

impl ClientHandle {
    /// Resolve a DM send target to the peer's DID when addressing-grade
    /// known (strict map only — never a display binding), else unchanged.
    /// Channels pass through. The signature canonical covers the resolved
    /// target, matching what the server verifies.
    fn resolve_wire_target(&self, target: &str) -> String {
        if target.starts_with('#') || target.starts_with('&') {
            return target.to_string();
        }
        self.did_maps.lock().wire_target(target)
    }

    /// The DID a DM to `target` will actually be addressed to, if the peer is
    /// addressing-grade known. `None` for a channel, and for a nick we hold no
    /// authoritative binding for.
    ///
    /// That `None` is the difference between a signed DM and an unsigned one:
    /// a bare nick has no venue any verifier could rebuild, so the signer
    /// declines it. A client that wants a first DM signed can ask the server
    /// who the peer is (WHOIS) and send once the answer lands.
    pub fn identified_dm_peer(&self, target: &str) -> Option<String> {
        if target.starts_with('#') || target.starts_with('&') {
            return None;
        }
        let resolved = self.resolve_wire_target(target);
        crate::address::is_did(&resolved).then_some(resolved)
    }

    pub async fn join(&self, channel: &str) -> Result<()> {
        self.cmd_tx.send(Command::Join(channel.to_string())).await?;
        Ok(())
    }

    /// Send a PRIVMSG. If `text` contains `\n` and the server acked
    /// `draft/multiline` + `batch`, the SDK auto-routes the send to a
    /// `draft/multiline` BATCH (one chunk per source line) so the
    /// wire stays valid. Single-line text goes out as one PRIVMSG
    /// unchanged.
    ///
    /// `\n`-bearing text against a server that didn't ack the cap
    /// still goes out as a single (malformed) PRIVMSG — callers
    /// targeting old servers should pre-encode or call
    /// `send_multiline_chunks` with explicit chunks.
    pub async fn privmsg(&self, target: &str, text: &str) -> Result<()> {
        let target = &self.resolve_wire_target(target);
        // Route through multiline when the text spans lines OR is long enough
        // that a single PRIVMSG would risk server-side truncation.
        let multiline_ready = (text.contains('\n') || text.len() > MULTILINE_PER_CHUNK_BYTES) && {
            let caps = self.caps_acked.lock();
            caps.acked.contains("draft/multiline") && caps.acked.contains("batch")
        };
        if multiline_ready {
            self.send_chunked_multiline(target, text, std::collections::HashMap::new())
                .await?;
        } else {
            self.cmd_tx
                .send(Command::Privmsg {
                    target: target.to_string(),
                    text: text.to_string(),
                    tags: std::collections::HashMap::new(),
                })
                .await?;
        }
        Ok(())
    }

    /// Send a multi-line message via `draft/multiline` BATCH. Splits
    /// `text` on `\n` boundaries by default — each logical line becomes
    /// one wire chunk with `concat=false` so receivers reassemble with
    /// `\n` separators. Pass `opener_tags` for client-only tags that
    /// should ride on the BATCH opener (e.g. commit-reveal payloads).
    ///
    /// For ciphertext-style chunking (one assembled blob split into
    /// fixed-size pieces with concat=true), construct the `Vec<MultilineChunk>`
    /// directly and use `send_multiline_chunks`.
    pub async fn send_multiline(
        &self,
        target: &str,
        text: &str,
        opener_tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        // Length-splits long lines into concat chunks and multi-batches when
        // the send exceeds the server's per-batch policy, so the assembled
        // body is byte-identical regardless of size.
        self.send_chunked_multiline(target, text, opener_tags).await
    }

    /// Lower-level multiline send: caller supplies the wire chunks
    /// directly. Use this when you need control over `concat` flags
    /// (e.g. splitting a single-line ciphertext into byte-sized pieces).
    pub async fn send_multiline_chunks(
        &self,
        target: &str,
        chunks: Vec<MultilineChunk>,
        opener_tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let target = &self.resolve_wire_target(target);
        self.cmd_tx
            .send(Command::SendMultiline {
                target: target.to_string(),
                chunks,
                opener_tags,
            })
            .await?;
        Ok(())
    }

    /// Chunk `text` for `draft/multiline` and emit it as one or more batches:
    /// long lines are hard-split into `concat` continuation chunks, and a send
    /// exceeding the server's per-batch policy is spread across several
    /// batches. The assembled body is byte-identical to `text`. `opener_tags`
    /// are applied to every emitted batch.
    async fn send_chunked_multiline(
        &self,
        target: &str,
        text: &str,
        opener_tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        // Respect the peer's advertised per-batch policy if it sent one,
        // else fall back to freeq's defaults. The per-chunk (per-line) budget
        // stays fixed — it's headroom under the wire cap, not a batch limit.
        let (max_bytes, max_lines) = self
            .caps_acked
            .lock()
            .multiline_policy
            .unwrap_or((MULTILINE_MAX_BYTES, MULTILINE_MAX_LINES));
        let chunks = chunk_multiline_body(text, MULTILINE_PER_CHUNK_BYTES);
        let groups = group_chunks_into_batches(chunks, max_lines, max_bytes);
        for group in groups {
            self.cmd_tx
                .send(Command::SendMultiline {
                    target: target.to_string(),
                    chunks: group,
                    opener_tags: opener_tags.clone(),
                })
                .await?;
        }
        Ok(())
    }

    pub async fn quit(&self, message: Option<&str>) -> Result<()> {
        self.cmd_tx
            .send(Command::Quit(message.map(|s| s.to_string())))
            .await?;
        Ok(())
    }

    pub async fn raw(&self, line: &str) -> Result<()> {
        self.cmd_tx.send(Command::Raw(line.to_string())).await?;
        Ok(())
    }

    /// Send a tagged message and await the server-assigned msgid via echo-message.
    ///
    /// This inserts a unique nonce tag (`+freeq.at/echo-nonce`) that the client
    /// loop matches against incoming echo-messages. Requires `echo-message` cap.
    ///
    /// Returns the server-assigned `msgid`.
    pub async fn send_and_await_echo(
        &self,
        target: &str,
        text: &str,
        mut tags: std::collections::HashMap<String, String>,
    ) -> Result<String> {
        let nonce = format!("echo-{:016x}", rand::random::<u64>());
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.echo_registry.lock().insert(nonce.clone(), tx);
        tags.insert("+freeq.at/echo-nonce".to_string(), nonce.clone());
        self.send_tagged(target, text, tags).await?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(msgid)) => Ok(msgid),
            Ok(Err(_)) => anyhow::bail!("Echo channel dropped"),
            Err(_) => {
                self.echo_registry.lock().remove(&nonce);
                anyhow::bail!("Timed out waiting for echo-message msgid")
            }
        }
    }

    /// Send a message with IRCv3 tags (for rich media). If `text`
    /// contains `\n` and the server acked `draft/multiline` + `batch`,
    /// the SDK auto-routes the send to a `draft/multiline` BATCH with
    /// the given tags on the opener — same auto-routing behavior as
    /// `privmsg`. Otherwise emits a single tagged PRIVMSG.
    pub async fn send_tagged(
        &self,
        target: &str,
        text: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let target = &self.resolve_wire_target(target);
        let multiline_ready = (text.contains('\n') || text.len() > MULTILINE_PER_CHUNK_BYTES) && {
            let caps = self.caps_acked.lock();
            caps.acked.contains("draft/multiline") && caps.acked.contains("batch")
        };
        if multiline_ready {
            self.send_chunked_multiline(target, text, tags).await?;
        } else {
            // Structured, not `Raw`: a tagged message is signed like any other
            // (its reply and coordination tags are inside the document), and
            // the signer has to see the tags to cover them.
            self.cmd_tx
                .send(Command::Privmsg {
                    target: target.to_string(),
                    text: text.to_string(),
                    tags,
                })
                .await?;
        }
        Ok(())
    }

    /// Send a media attachment to a target (channel or user).
    pub async fn send_media(
        &self,
        target: &str,
        media: &crate::media::MediaAttachment,
    ) -> Result<()> {
        self.send_tagged(target, &media.fallback_text(), media.to_tags())
            .await
    }

    /// Send a TAGMSG (tags-only, no body) to a target.
    ///
    /// Structured, not `Raw`: a delete or a reaction is signed over the tags
    /// that carry it, and one place has to see them to sign them.
    ///
    /// A DM peer resolves to their DID exactly as it does for a message send —
    /// the signer derives the venue from the target it is handed, so routing
    /// a mutation to a bare nick when the DID is known would send it unsigned
    /// for no reason.
    pub async fn send_tagmsg(
        &self,
        target: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let target = self.resolve_wire_target(target);
        self.cmd_tx.send(Command::Tagmsg { target, tags }).await?;
        Ok(())
    }

    /// Send a task event: the signed TAGMSG that *is* the event, then the
    /// plain-text companion that renders it for people. Returns the event's
    /// id — which, for an opener, is the task's id for the rest of its life.
    ///
    /// `tags` is the whole document, built by [`crate::act::act_tags`] or by
    /// hand. Nothing here reads it: this sends whatever act tags it is given,
    /// under any kind and any verb, and which verbs a kind allows is the rules
    /// file's business, not this method's.
    ///
    /// `human_text` follows [`ClientHandle::quit`]'s shape: `None` for the
    /// line [`crate::act::act_line`] writes for these tags, `Some("")` for no
    /// companion at all, `Some(line)` for the caller's own words.
    ///
    /// The one place this differs from every other send here: **it never falls
    /// back to unsigned**. A message sent without a signature is still a
    /// message, but an unsigned task event is refused at the server's door and
    /// asserts nothing — so no key, no account, or a bare-nick DM with no
    /// venue a verifier could rebuild is an error the caller is handed.
    pub async fn send_act(
        &self,
        target: &str,
        tags: std::collections::HashMap<String, String>,
        human_text: Option<&str>,
    ) -> Result<String> {
        let event_id = crate::chatsig::new_event_id();
        let human_text = match human_text {
            Some(line) => line.to_string(),
            None => {
                let kind = tags
                    .get("+freeq.at/act")
                    .map(String::as_str)
                    .unwrap_or_default();
                let verb = tags
                    .get("+freeq.at/act-verb")
                    .map(String::as_str)
                    .unwrap_or_default();
                let fields: Vec<(&str, &str)> = tags
                    .iter()
                    .filter_map(|(name, value)| {
                        name.strip_prefix("+freeq.at/act-")
                            .map(|field| (field, value.as_str()))
                    })
                    .collect();
                crate::act::act_line(kind, verb, &fields)
            }
        };
        let (done, answer) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Command::Act {
                target: self.resolve_wire_target(target),
                event_id: event_id.clone(),
                tags,
                human_text,
                done,
            })
            .await?;
        answer.await.map_err(|_| {
            anyhow::anyhow!("the connection ended before the task event was sent")
        })??;
        Ok(event_id)
    }

    /// Start a new AV (voice/video) call in `channel`. The server
    /// replies with an `av-state` TAGMSG carrying the session id —
    /// watch for it with [`crate::av::parse_av_state`] applied to
    /// incoming [`Event::TagMsg`](crate::event::Event::TagMsg) tags.
    /// `instance` is a per-call id from [`crate::av::new_av_instance`].
    pub async fn av_start(&self, channel: &str, instance: &str, title: Option<&str>) -> Result<()> {
        self.send_tagmsg(channel, crate::av::av_start_tags(instance, title))
            .await
    }

    /// Join the active AV call in `channel`. `session_id` is the id from
    /// the channel's `av-state` broadcast.
    pub async fn av_join(&self, channel: &str, session_id: &str, instance: &str) -> Result<()> {
        self.send_tagmsg(channel, crate::av::av_join_tags(session_id, instance))
            .await
    }

    /// Leave an AV call.
    pub async fn av_leave(&self, channel: &str, session_id: &str, instance: &str) -> Result<()> {
        self.send_tagmsg(channel, crate::av::av_leave_tags(session_id, instance))
            .await
    }

    /// Send a reaction to a target (channel or user).
    /// Falls back to PRIVMSG for plain clients.
    pub async fn send_reaction(
        &self,
        target: &str,
        reaction: &crate::media::Reaction,
    ) -> Result<()> {
        self.send_tagmsg(target, reaction.to_tags()).await
    }

    /// Send a link preview as a tagged message.
    pub async fn send_link_preview(
        &self,
        target: &str,
        preview: &crate::media::LinkPreview,
    ) -> Result<()> {
        let fallback = match (&preview.title, &preview.description) {
            (Some(t), Some(d)) => format!("🔗 {} — {} ({})", t, d, preview.url),
            (Some(t), None) => format!("🔗 {} ({})", t, preview.url),
            _ => format!("🔗 {}", preview.url),
        };
        self.send_tagged(target, &fallback, preview.to_tags()).await
    }

    // ── Convenience helpers ──

    /// Send a reply to a specific message (adds +reply tag).
    pub async fn reply(&self, target: &str, msgid: &str, text: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+reply".to_string(), msgid.to_string());
        self.send_tagged(target, text, tags).await
    }

    /// Send a reply in a thread (same as reply — thread parent is the msgid).
    pub async fn reply_in_thread(
        &self,
        target: &str,
        parent_msgid: &str,
        text: &str,
    ) -> Result<()> {
        self.reply(target, parent_msgid, text).await
    }

    /// Send a typing indicator start.
    pub async fn typing_start(&self, target: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+typing".to_string(), "active".to_string());
        self.send_tagmsg(target, tags).await
    }

    /// Send a typing indicator stop.
    pub async fn typing_stop(&self, target: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+typing".to_string(), "done".to_string());
        self.send_tagmsg(target, tags).await
    }

    /// Join multiple channels at once.
    pub async fn join_many(&self, channels: &[&str]) -> Result<()> {
        if channels.is_empty() {
            return Ok(());
        }
        // IRC allows comma-separated JOIN
        let joined = channels.join(",");
        self.raw(&format!("JOIN {joined}")).await
    }

    /// Set a channel mode. Examples: `mode("#chan", "+o", Some("nick"))`.
    pub async fn mode(&self, channel: &str, flags: &str, arg: Option<&str>) -> Result<()> {
        match arg {
            Some(a) => self.raw(&format!("MODE {channel} {flags} {a}")).await,
            None => self.raw(&format!("MODE {channel} {flags}")).await,
        }
    }

    /// Request latest N messages of history (CHATHISTORY LATEST).
    pub async fn history_latest(&self, target: &str, count: usize) -> Result<()> {
        self.raw(&format!("CHATHISTORY LATEST {target} * {count}"))
            .await
    }

    /// Request N messages before a given msgid (CHATHISTORY BEFORE).
    pub async fn history_before(&self, target: &str, msgid: &str, count: usize) -> Result<()> {
        self.raw(&format!(
            "CHATHISTORY BEFORE {target} msgid={msgid} {count}"
        ))
        .await
    }

    /// Request N messages after a given msgid (CHATHISTORY AFTER).
    pub async fn history_after(&self, target: &str, msgid: &str, count: usize) -> Result<()> {
        self.raw(&format!("CHATHISTORY AFTER {target} msgid={msgid} {count}"))
            .await
    }

    /// Request DM conversation list (CHATHISTORY TARGETS).
    pub async fn chathistory_targets(&self, limit: usize) -> Result<()> {
        self.raw(&format!("CHATHISTORY TARGETS * * {limit}")).await
    }

    /// Send a reaction emoji to a specific message.
    pub async fn react(&self, target: &str, emoji: &str, msgid: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+react".to_string(), emoji.to_string());
        tags.insert("+reply".to_string(), msgid.to_string());
        self.send_tagmsg(target, tags).await
    }

    /// Remove a reaction emoji you previously added to a message.
    ///
    /// The mirror of [`react`](Self::react): same target, same emoji, same
    /// message. The removal is a mutation like any other — it is signed and
    /// filed under an event id of its own, so history records who withdrew
    /// the reaction rather than silently losing that it was ever there.
    pub async fn unreact(&self, target: &str, emoji: &str, msgid: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+freeq.at/unreact".to_string(), emoji.to_string());
        tags.insert("+reply".to_string(), msgid.to_string());
        self.send_tagmsg(target, tags).await
    }

    /// Edit a previously sent message.
    pub async fn edit_message(
        &self,
        target: &str,
        original_msgid: &str,
        new_text: &str,
    ) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+draft/edit".to_string(), original_msgid.to_string());
        self.send_tagged(target, new_text, tags).await
    }

    /// Delete a previously sent message (via TAGMSG).
    pub async fn delete_message(&self, target: &str, msgid: &str) -> Result<()> {
        let mut tags = std::collections::HashMap::new();
        tags.insert("+draft/delete".to_string(), msgid.to_string());
        self.send_tagmsg(target, tags).await
    }

    /// Pin a message in a channel.
    pub async fn pin(&self, channel: &str, msgid: &str) -> Result<()> {
        self.raw(&format!("PIN {channel} {msgid}")).await
    }

    /// Unpin a message in a channel.
    pub async fn unpin(&self, channel: &str, msgid: &str) -> Result<()> {
        self.raw(&format!("UNPIN {channel} {msgid}")).await
    }

    /// Set the channel topic.
    pub async fn topic(&self, channel: &str, topic: &str) -> Result<()> {
        self.raw(&format!("TOPIC {channel} :{topic}")).await
    }

    /// Ask the server who `nick` is.
    ///
    /// The answer arrives asynchronously: the account binding in RPL_WHOISACCOUNT
    /// (330) surfaces as [`Event::MemberDid`](crate::event::Event::MemberDid), the
    /// rest as [`Event::WhoisReply`](crate::event::Event::WhoisReply). Callers that
    /// need the DID before sending — a first DM to a bare nick — watch for the
    /// former.
    pub async fn whois(&self, nick: &str) -> Result<()> {
        self.raw(&format!("WHOIS {nick}")).await
    }

    // ── Read markers (draft/read-marker) ──────────────────────────────

    /// Set the cross-device read marker for `target` to `timestamp`.
    ///
    /// `timestamp` must be ISO 8601 with millisecond precision and a `Z`
    /// suffix, exactly as in the `server-time` extension
    /// (`YYYY-MM-DDThh:mm:ss.sssZ`). The server only moves the marker forward:
    /// a stale timestamp is ignored and the server replies with the current
    /// (newer) value. Either way the reply arrives as [`Event::ReadMarker`],
    /// and — for DID-authenticated sessions — the same update is pushed to your
    /// other connected devices.
    pub async fn mark_read(&self, target: &str, timestamp: &str) -> Result<()> {
        self.raw(&format!("MARKREAD {target} timestamp={timestamp}"))
            .await
    }

    /// Query the current read marker for `target`. The answer arrives as
    /// [`Event::ReadMarker`] with `timestamp: None` when no marker has been set.
    pub async fn get_read_marker(&self, target: &str) -> Result<()> {
        self.raw(&format!("MARKREAD {target}")).await
    }

    // ── Agent-native methods ─────────────────────────────────────────

    /// Register this connection as an agent (or external_agent).
    pub async fn register_agent(&self, class: &str) -> Result<()> {
        self.raw(&format!("AGENT REGISTER :class={class}")).await
    }

    /// Submit a provenance declaration (JSON value, will be base64url-encoded).
    pub async fn submit_provenance(&self, provenance: &serde_json::Value) -> Result<()> {
        let json = serde_json::to_vec(provenance)?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);
        self.raw(&format!("PROVENANCE :{encoded}")).await
    }

    /// Update structured agent presence.
    pub async fn set_presence(
        &self,
        state: &str,
        status: Option<&str>,
        task: Option<&str>,
    ) -> Result<()> {
        let mut parts = vec![format!("state={state}")];
        if let Some(s) = status {
            parts.push(format!("status={s}"));
        }
        if let Some(t) = task {
            parts.push(format!("task={t}"));
        }
        self.raw(&format!("PRESENCE :{}", parts.join(";"))).await
    }

    /// Send a heartbeat with the given state and TTL (seconds).
    pub async fn send_heartbeat(&self, state: &str, ttl: u64) -> Result<()> {
        self.raw(&format!("HEARTBEAT :state={state};ttl={ttl}"))
            .await
    }

    /// Request approval for a capability in a channel.
    pub async fn request_approval(
        &self,
        channel: &str,
        capability: &str,
        resource: Option<&str>,
    ) -> Result<()> {
        let resource_part = resource
            .map(|r| format!(";resource={r}"))
            .unwrap_or_default();
        self.raw(&format!(
            "APPROVAL_REQUEST {channel} :{capability}{resource_part}"
        ))
        .await
    }

    /// Pause an agent (must be op in shared channel).
    pub async fn pause_agent(&self, nick: &str, reason: Option<&str>) -> Result<()> {
        match reason {
            Some(r) => self.raw(&format!("AGENT PAUSE {nick} :{r}")).await,
            None => self.raw(&format!("AGENT PAUSE {nick}")).await,
        }
    }

    /// Resume an agent (must be op in shared channel).
    pub async fn resume_agent(&self, nick: &str) -> Result<()> {
        self.raw(&format!("AGENT RESUME {nick}")).await
    }

    /// Revoke an agent (must be op in shared channel).
    pub async fn revoke_agent(&self, nick: &str, reason: Option<&str>) -> Result<()> {
        match reason {
            Some(r) => self.raw(&format!("AGENT REVOKE {nick} :{r}")).await,
            None => self.raw(&format!("AGENT REVOKE {nick}")).await,
        }
    }

    /// Approve an agent's pending capability request.
    pub async fn approve_agent(&self, nick: &str, capability: &str) -> Result<()> {
        self.raw(&format!("AGENT APPROVE {nick} {capability}"))
            .await
    }

    /// Deny an agent's pending capability request.
    pub async fn deny_agent(
        &self,
        nick: &str,
        capability: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        match reason {
            Some(r) => {
                self.raw(&format!("AGENT DENY {nick} {capability} :{r}"))
                    .await
            }
            None => self.raw(&format!("AGENT DENY {nick} {capability}")).await,
        }
    }

    // ── Phase 3: Coordination events ────────────────────────────────

    /// Emit a typed coordination event to a channel.
    /// Sends both a TAGMSG (structured, for rich clients) and PRIVMSG (human-readable).
    ///
    /// Against a server that verifies documents the TAGMSG is signed over its
    /// own coordination document and filed under a signer-minted ULID; against
    /// one that doesn't, the pair is byte-for-byte what a pre-signing client
    /// sent, legacy id and all. Either way the returned id is the id the
    /// server files, because callers reference it.
    pub async fn emit_event(
        &self,
        channel: &str,
        event_type: &str,
        payload_json: &str,
        ref_id: Option<&str>,
        human_text: &str,
    ) -> Result<String> {
        self.emit_event_with_evidence(channel, event_type, payload_json, ref_id, None, human_text)
            .await
    }

    /// [`Self::emit_event`], plus the evidence type an `evidence_attach`
    /// carries. Private: the public shape stays as it was, and the only
    /// caller is [`Self::attach_evidence`].
    async fn emit_event_with_evidence(
        &self,
        channel: &str,
        event_type: &str,
        payload_json: &str,
        ref_id: Option<&str>,
        evidence_type: Option<&str>,
        human_text: &str,
    ) -> Result<String> {
        // Decided here, not at the wire, because the id is returned now: a
        // signed event is filed under the ULID its signature covers, an
        // unsigned one under the legacy id the server reads from `msgid`.
        let signs = self.caps_acked.lock().acked.contains(MSGSIG_CAP);
        let event_id = if signs {
            crate::chatsig::new_event_id()
        } else {
            legacy_event_id()
        };
        self.cmd_tx
            .send(Command::CoordinationEvent {
                channel: channel.to_string(),
                event_id: event_id.clone(),
                event_type: event_type.to_string(),
                payload: payload_json.replace(';', "%3B").replace(' ', "%20"),
                ref_id: ref_id.map(str::to_string),
                evidence_type: evidence_type.map(str::to_string),
                human_text: human_text.to_string(),
            })
            .await?;
        Ok(event_id)
    }

    /// Create a new task and return its ID.
    ///
    /// Superseded by [`ClientHandle::send_act`] carrying an `offer` built by
    /// [`crate::act::act_tags`] — the same work opened as a signed task event
    /// the sender then holds by accepting it. This one keeps sending the older
    /// task family until every caller has moved.
    pub async fn create_task(&self, channel: &str, description: &str) -> Result<String> {
        let payload = serde_json::json!({"description": description}).to_string();
        self.emit_event(
            channel,
            "task_request",
            &payload,
            None,
            &format!("📋 New task: {description}"),
        )
        .await
    }

    /// Update a task's status.
    ///
    /// Superseded by [`ClientHandle::send_act`] carrying a `progress` built by
    /// [`crate::act::act_tags`], which says the same thing on the task's own
    /// record. This one keeps sending the older task family until every caller
    /// has moved.
    pub async fn update_task(
        &self,
        channel: &str,
        task_id: &str,
        phase: &str,
        summary: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({"phase": phase, "summary": summary}).to_string();
        self.emit_event(
            channel,
            "task_update",
            &payload,
            Some(task_id),
            &format!("🔄 [{phase}] {summary}"),
        )
        .await?;
        Ok(())
    }

    /// Complete a task.
    ///
    /// Superseded by [`ClientHandle::send_act`] carrying a `complete` built by
    /// [`crate::act::act_tags`]. This one keeps sending the older task family
    /// until every caller has moved.
    pub async fn complete_task(
        &self,
        channel: &str,
        task_id: &str,
        summary: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let mut payload = serde_json::json!({"summary": summary});
        if let Some(u) = url {
            payload["url"] = serde_json::json!(u);
        }
        let url_str = url.map(|u| format!(" — {u}")).unwrap_or_default();
        self.emit_event(
            channel,
            "task_complete",
            &payload.to_string(),
            Some(task_id),
            &format!("🎉 Task complete: {summary}{url_str}"),
        )
        .await?;
        Ok(())
    }

    /// Fail a task.
    ///
    /// Superseded by [`ClientHandle::send_act`] carrying a `fail` built by
    /// [`crate::act::act_tags`]. This one keeps sending the older task family
    /// until every caller has moved.
    pub async fn fail_task(&self, channel: &str, task_id: &str, error: &str) -> Result<()> {
        let payload = serde_json::json!({"error": error}).to_string();
        self.emit_event(
            channel,
            "task_failed",
            &payload,
            Some(task_id),
            &format!("❌ Task failed: {error}"),
        )
        .await?;
        Ok(())
    }

    /// Attach evidence to a task.
    ///
    /// Superseded by [`ClientHandle::send_act`] carrying a `progress` built by
    /// [`crate::act::act_tags`] with `ctx` and `ctx-h` fields — the materials
    /// and a hash of them, so what is fetched later is checkable against what
    /// was signed. This one keeps sending the older task family until every
    /// caller has moved.
    pub async fn attach_evidence(
        &self,
        channel: &str,
        task_id: &str,
        evidence_type: &str,
        summary: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let mut payload = serde_json::json!({
            "type": evidence_type,
            "summary": summary,
        });
        if let Some(u) = url {
            payload["url"] = serde_json::json!(u);
        }
        let url_str = url.map(|u| format!(" — {u}")).unwrap_or_default();
        // The type rides as a tag as well as inside the payload: the tag is
        // what a reader renders and a bot reads, and both SDKs send it so the
        // same event is covered the same way whichever emitted it.
        self.emit_event_with_evidence(
            channel,
            "evidence_attach",
            &payload.to_string(),
            Some(task_id),
            Some(evidence_type),
            &format!("📎 Evidence ({evidence_type}): {summary}{url_str}"),
        )
        .await?;
        Ok(())
    }

    // ── Phase 4: Manifests and Spawning ────────────────────────────

    /// Submit an agent manifest (base64-encoded TOML).
    pub async fn submit_manifest(&self, toml_content: &str) -> Result<()> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(toml_content.as_bytes());
        self.raw(&format!("AGENT MANIFEST {encoded}")).await
    }

    /// Spawn a child agent in a channel.
    pub async fn spawn_agent(
        &self,
        channel: &str,
        nick: &str,
        capabilities: &[&str],
        ttl_seconds: Option<u64>,
        task_ref: Option<&str>,
    ) -> Result<()> {
        let mut params = format!("nick={nick}");
        if !capabilities.is_empty() {
            params.push_str(&format!(";capabilities={}", capabilities.join(",")));
        }
        if let Some(ttl) = ttl_seconds {
            params.push_str(&format!(";ttl={ttl}"));
        }
        if let Some(task) = task_ref {
            params.push_str(&format!(";task={task}"));
        }
        self.raw(&format!("AGENT SPAWN {channel} :{params}")).await
    }

    /// Despawn a child agent.
    pub async fn despawn_agent(&self, nick: &str) -> Result<()> {
        self.raw(&format!("AGENT DESPAWN {nick}")).await
    }

    /// Send a message as a spawned child agent.
    pub async fn send_as_child(&self, child_nick: &str, channel: &str, text: &str) -> Result<()> {
        self.raw(&format!("AGENT MSG {child_nick} {channel} :{text}"))
            .await
    }

    // ── Phase 5: Economic Controls ─────────────────────────────────

    /// Report spend for the current action.
    pub async fn report_spend(
        &self,
        channel: &str,
        amount: f64,
        unit: &str,
        description: &str,
        task_ref: Option<&str>,
    ) -> Result<()> {
        let mut params = format!("amount={amount:.6};unit={unit};desc={description}");
        if let Some(task) = task_ref {
            params.push_str(&format!(";task={task}"));
        }
        self.raw(&format!("SPEND {channel} :{params}")).await
    }

    /// Set a channel budget (must be channel op).
    pub async fn set_budget(
        &self,
        channel: &str,
        max_amount: f64,
        unit: &str,
        period: &str,
        sponsor_did: &str,
    ) -> Result<()> {
        self.raw(&format!(
            "BUDGET {channel} :max={max_amount};unit={unit};period={period};sponsor={sponsor_did}"
        ))
        .await
    }

    /// Query channel budget status.
    pub async fn query_budget(&self, channel: &str) -> Result<()> {
        self.raw(&format!("BUDGET {channel}")).await
    }

    /// Start automatic heartbeat in a background task.
    /// Returns a handle that stops the heartbeat when dropped.
    pub fn start_heartbeat(&self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        let ttl = interval.as_secs() * 2;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if handle.send_heartbeat("active", ttl).await.is_err() {
                    break; // Connection closed
                }
            }
        })
    }
}

/// Establish TCP (and optionally TLS) connection to the server.
///
/// This is done **before** the TUI starts so that connection errors
/// are visible on stderr. Returns the established connection for
/// `connect_with_stream` to use.
/// Cap any single transport-layer connect attempt at this duration. The
/// underlying OS TCP timeout on iOS/macOS is ~75s — that's the cliff that
/// produces the user-visible "Connecting…" hang on networks that drop the
/// SYN to port 6667 silently. 10s is long enough for any real network and
/// short enough to fall through to a WebSocket fallback in time.
pub const TRANSPORT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn establish_connection(config: &ConnectConfig) -> Result<EstablishedConnection> {
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid ConnectConfig: {e}"))?;

    // If a WebSocket URL is configured, prefer that transport. iOS sets this
    // so it can reach the server on networks that block port 6667.
    #[cfg(feature = "websocket")]
    if let Some(ref ws_url) = config.websocket_url {
        return establish_ws_connection(ws_url).await;
    }

    // Auto-detect TLS from port if not explicitly set
    let use_tls = config.tls || config.server_addr.ends_with(":6697");
    let mode = if use_tls { "TLS" } else { "plain" };

    tracing::debug!("Resolving {}...", config.server_addr);
    let tcp = match tokio::time::timeout(
        TRANSPORT_CONNECT_TIMEOUT,
        TcpStream::connect(&config.server_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!(
                "TCP connect to {} failed: {e}",
                config.server_addr
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "TCP connect to {} timed out after {}s",
                config.server_addr,
                TRANSPORT_CONNECT_TIMEOUT.as_secs()
            ));
        }
    };
    tracing::debug!("TCP connected to {} ({mode})", config.server_addr);

    if use_tls {
        let tls_config = if config.tls_insecure {
            tracing::debug!("TLS: insecure mode (skipping cert verification)");
            rustls_insecure_config()
        } else {
            tracing::debug!("TLS: verifying server certificate...");
            rustls_default_config()
        };
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = config.server_addr.split(':').next().unwrap_or("localhost");
        let dns_name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let tls_stream = connector.connect(dns_name, tcp).await.map_err(|e| {
            let hint = if format!("{e}").contains("UnknownIssuer") {
                " (the server's certificate chain may be incomplete — try --tls-insecure to skip verification, or ensure the server sends its full certificate chain including intermediates)"
            } else {
                ""
            };
            anyhow::anyhow!("TLS handshake with {} failed: {e}{hint}", config.server_addr)
        })?;
        tracing::debug!("TLS handshake complete");
        Ok(EstablishedConnection::Tls(tls_stream))
    } else {
        Ok(EstablishedConnection::Plain(tcp))
    }
}

/// A connection that has completed TCP (and optionally TLS) but hasn't
/// started IRC registration yet.
pub enum EstablishedConnection {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    /// Iroh QUIC connection (already encrypted, NAT-traversing).
    #[cfg(feature = "iroh-transport")]
    Iroh(tokio::io::DuplexStream),
    /// WebSocket connection (encrypted via TLS for `wss://`). The client
    /// speaks raw IRC line bytes; the bridge tasks frame them as
    /// WebSocket text messages and unframe inbound messages identically.
    /// Reuses the same `DuplexStream` plumbing as Iroh so `run_irc()`
    /// doesn't need to know which transport it's running over.
    #[cfg(feature = "websocket")]
    WebSocket(tokio::io::DuplexStream),
}

/// ALPN for IRC-over-iroh (must match server).
#[cfg(feature = "iroh-transport")]
pub const IROH_ALPN: &[u8] = b"freeq/iroh/1";

#[cfg(feature = "iroh-transport")]
/// Establish a connection to an IRC server via iroh.
///
/// `addr` is the iroh endpoint address string (EndpointAddr format).
pub async fn establish_iroh_connection(addr: &str) -> Result<EstablishedConnection> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::debug!("Creating iroh endpoint...");
    let endpoint = iroh::Endpoint::bind(iroh::endpoint::presets::N0).await?;

    tracing::debug!("Connecting to iroh peer {addr}...");
    // Parse the endpoint ID (public key) and create an address.
    // Iroh's relay/discovery system handles finding the actual network path.
    let endpoint_id: iroh::EndpointId = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid iroh endpoint ID '{addr}': {e}"))?;
    let endpoint_addr = iroh::EndpointAddr::new(endpoint_id);
    let conn = endpoint.connect(endpoint_addr, IROH_ALPN).await?;
    tracing::debug!("Iroh QUIC connection established (encrypted)");

    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {e}"))?;
    tracing::debug!("Bidirectional stream open, ready for IRC");

    // Bridge QUIC send/recv to a DuplexStream that the IRC handler can use.
    // irc_side goes to the IRC protocol handler.
    // bridge_side is shuttled to/from QUIC by two background tasks.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // QUIC recv → bridge_write → IRC handler reads from irc_side
    tokio::spawn(async move {
        let mut recv = recv;
        let mut buf = vec![0u8; 4096];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if bridge_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = bridge_write.shutdown().await;
    });

    // IRC handler writes to irc_side → bridge_read → QUIC send
    tokio::spawn(async move {
        let mut send = send;
        let mut buf = vec![0u8; 4096];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send.finish();
    });

    // Keep endpoint + connection alive for the lifetime of the session
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _conn = conn;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });

    Ok(EstablishedConnection::Iroh(irc_side))
}

/// Probe an IRC server for iroh endpoint ID via CAP LS.
///
/// Connects via TCP (or TLS for port 6697), sends CAP LS, reads the response,
/// extracts `iroh=<endpoint-id>` if present, and disconnects cleanly.
/// Returns `None` if the server doesn't advertise iroh.
///
/// This enables automatic iroh transport upgrade: connect cheap (TCP),
/// discover capabilities, reconnect optimal (iroh QUIC).
#[cfg(feature = "iroh-transport")]
pub async fn discover_iroh_id(server_addr: &str, tls: bool, tls_insecure: bool) -> Option<String> {
    use std::time::Duration;
    use tokio::time::timeout;

    let use_tls = tls || server_addr.ends_with(":6697");

    // Give the probe 5 seconds max
    let result = timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect(server_addr).await.ok()?;

        if use_tls {
            let tls_config = if tls_insecure {
                rustls_insecure_config()
            } else {
                rustls_default_config()
            };
            let connector = TlsConnector::from(Arc::new(tls_config));
            let host = server_addr.split(':').next().unwrap_or("localhost");
            let dns_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
            let tls_stream = connector.connect(dns_name, tcp).await.ok()?;
            probe_cap_ls(tls_stream).await
        } else {
            probe_cap_ls(tcp).await
        }
    })
    .await;

    result.ok().flatten()
}

/// Send CAP LS and parse iroh endpoint ID from response.
async fn probe_cap_ls<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
) -> Option<String> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Send CAP LS and a throwaway NICK/USER so the server doesn't time us out
    writer
        .write_all(b"CAP LS 302\r\nNICK _probe\r\nUSER _probe 0 * :probe\r\n")
        .await
        .ok()?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.ok()?;
        if n == 0 {
            return None;
        }

        // Look for CAP * LS :...
        if line.contains("CAP") && line.contains("LS") {
            // Find iroh=<id> in the caps string
            for token in line.split_whitespace() {
                if let Some(id) = token.strip_prefix("iroh=") {
                    // Clean up: send QUIT
                    let _ = writer.write_all(b"QUIT\r\n").await;
                    let _ = writer.shutdown().await;
                    return Some(id.trim().to_string());
                }
            }
            // Server responded to CAP LS but no iroh — done
            let _ = writer.write_all(b"QUIT\r\n").await;
            let _ = writer.shutdown().await;
            return None;
        }
    }
}

/// Connect using an already-established connection.
///
/// Returns a handle for sending commands and a receiver for events.
/// The IRC protocol runs in a spawned task.
pub fn connect_with_stream(
    conn: EstablishedConnection,
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let (event_tx, event_rx) = mpsc::channel(4096);
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let echo_registry: EchoRegistry = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
    let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));

    let handle = ClientHandle {
        cmd_tx: cmd_tx.clone(),
        echo_registry: echo_registry.clone(),
        caps_acked: caps_acked.clone(),
        did_maps: did_maps.clone(),
    };

    let echo_reg = echo_registry.clone();
    let caps_for_loop = caps_acked.clone();
    let maps_for_loop = did_maps.clone();
    tokio::spawn(async move {
        let _ = event_tx.send(Event::Connected).await;
        let result = match conn {
            EstablishedConnection::Plain(tcp) => {
                let (reader, writer) = tokio::io::split(tcp);
                run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    signer,
                    event_tx.clone(),
                    cmd_rx,
                    echo_reg,
                    caps_for_loop,
                    maps_for_loop,
                )
                .await
            }
            EstablishedConnection::Tls(tls) => {
                let (reader, writer) = tokio::io::split(tls);
                run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    signer,
                    event_tx.clone(),
                    cmd_rx,
                    echo_reg,
                    caps_for_loop,
                    maps_for_loop,
                )
                .await
            }
            #[cfg(feature = "iroh-transport")]
            EstablishedConnection::Iroh(duplex) => {
                let (reader, writer) = tokio::io::split(duplex);
                run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    signer,
                    event_tx.clone(),
                    cmd_rx,
                    echo_reg,
                    caps_for_loop,
                    maps_for_loop,
                )
                .await
            }
            #[cfg(feature = "websocket")]
            EstablishedConnection::WebSocket(duplex) => {
                let (reader, writer) = tokio::io::split(duplex);
                run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    signer,
                    event_tx.clone(),
                    cmd_rx,
                    echo_reg,
                    caps_for_loop,
                    maps_for_loop,
                )
                .await
            }
        };
        if let Err(e) = result {
            let _ = event_tx
                .send(Event::Disconnected {
                    reason: e.to_string(),
                })
                .await;
        }
    });

    (handle, event_rx)
}

/// Connect to an IRC server and run the client.
///
/// Returns a handle for sending commands and a receiver for events.
/// The connection runs in a spawned task.
///
/// Note: prefer `establish_connection` + `connect_with_stream` for better
/// error reporting (connection errors happen before the TUI starts).
pub fn connect(
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let (event_tx, event_rx) = mpsc::channel(4096);
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let echo_registry: EchoRegistry = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
    let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));

    let handle = ClientHandle {
        cmd_tx: cmd_tx.clone(),
        echo_registry: echo_registry.clone(),
        caps_acked: caps_acked.clone(),
        did_maps: did_maps.clone(),
    };

    let echo_reg = echo_registry.clone();
    let caps_for_loop = caps_acked.clone();
    let maps_for_loop = did_maps.clone();
    tokio::spawn(async move {
        if let Err(e) = run_client(
            config,
            signer,
            event_tx.clone(),
            cmd_rx,
            echo_reg,
            caps_for_loop,
            maps_for_loop,
        )
        .await
        {
            let _ = event_tx
                .send(Event::Disconnected {
                    reason: e.to_string(),
                })
                .await;
        }
    });

    (handle, event_rx)
}

async fn run_client(
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    event_tx: mpsc::Sender<Event>,
    cmd_rx: mpsc::Receiver<Command>,
    echo_registry: EchoRegistry,
    caps_acked: CapsAcked,
    did_maps: DidMaps,
) -> Result<()> {
    let conn = establish_connection(&config).await?;
    let _ = event_tx.send(Event::Connected).await;
    match conn {
        EstablishedConnection::Plain(tcp) => {
            let (reader, writer) = tokio::io::split(tcp);
            run_irc(
                BufReader::new(reader),
                writer,
                &config,
                signer,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await
        }
        EstablishedConnection::Tls(tls) => {
            let (reader, writer) = tokio::io::split(tls);
            run_irc(
                BufReader::new(reader),
                writer,
                &config,
                signer,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await
        }
        #[cfg(feature = "iroh-transport")]
        EstablishedConnection::Iroh(duplex) => {
            let (reader, writer) = tokio::io::split(duplex);
            run_irc(
                BufReader::new(reader),
                writer,
                &config,
                signer,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await
        }
        #[cfg(feature = "websocket")]
        EstablishedConnection::WebSocket(duplex) => {
            let (reader, writer) = tokio::io::split(duplex);
            run_irc(
                BufReader::new(reader),
                writer,
                &config,
                signer,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await
        }
    }
}

/// Connect via WebSocket and bridge the framed transport to a `DuplexStream`
/// that `run_irc()` reads/writes as plain IRC bytes.
///
/// The server-side counterpart is `freeq-server/src/web.rs::bridge_ws()`,
/// which terminates the WebSocket and feeds bytes into the same IRC handler
/// it uses for raw TCP. Here we do the mirror: outbound bytes from
/// `run_irc` are wrapped in `WsMessage::Text`, and inbound text/binary
/// frames are written back into the duplex.
#[cfg(feature = "websocket")]
async fn establish_ws_connection(url: &str) -> Result<EstablishedConnection> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    // The rustls default crypto provider must be installed before any TLS
    // handshake — including the one tokio-tungstenite does internally for
    // wss://. The TCP-with-TLS path covers this in `rustls_default_config()`,
    // but the WebSocket path bypasses that helper, so the install was being
    // skipped and the wss handshake silently hung.
    install_crypto_provider();

    tracing::debug!("Connecting WebSocket {url}...");
    let connect_result = tokio::time::timeout(
        TRANSPORT_CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async(url),
    )
    .await;
    let (ws, _resp) = match connect_result {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(anyhow::anyhow!("WebSocket connect to {url} failed: {e}")),
        Err(_) => {
            return Err(anyhow::anyhow!(
                "WebSocket connect to {url} timed out after {}s",
                TRANSPORT_CONNECT_TIMEOUT.as_secs()
            ));
        }
    };
    tracing::debug!("WebSocket connected: {url}");

    // 64 KiB matches the JS transport's bufferedAmount threshold and gives
    // both directions room without unbounded memory.
    let (client_side, bridge_side) = tokio::io::duplex(65_536);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge_side);
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Wire framing: mirror what `freeq-server/src/web.rs::bridge_ws()` does
    // on the server side. One WebSocket text frame == one IRC line without
    // its trailing CRLF. The server appends `\r\n` on receive and strips it
    // before forwarding outbound frames; we do the symmetric thing here.

    // Outbound: read CRLF-terminated lines from `run_irc`'s write half and
    // emit each as its own WS text frame (without the CRLF).
    tokio::spawn(async move {
        tracing::info!("WS: outbound bridge task started");
        let mut buf = vec![0u8; 4096];
        let mut line_buf: Vec<u8> = Vec::new();
        let mut frames_out: u64 = 0;
        loop {
            match bridge_reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::warn!(frames_out, "WS: outbound EOF on bridge_read");
                    break;
                }
                Ok(n) => {
                    line_buf.extend_from_slice(&buf[..n]);
                    while let Some(pos) = line_buf.windows(2).position(|w| w == b"\r\n") {
                        let line = String::from_utf8_lossy(&line_buf[..pos]).into_owned();
                        line_buf.drain(..pos + 2);
                        frames_out += 1;
                        let preview: String = line.chars().take(80).collect();
                        tracing::debug!(n = frames_out, preview = %preview, "WS: → text frame");
                        if let Err(e) = ws_writer.send(WsMessage::Text(line.into())).await {
                            tracing::warn!("WS: outbound send error: {e}");
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("WS: bridge_read error: {e}");
                    break;
                }
            }
        }
        tracing::warn!(frames_out, "WS: outbound bridge task ending");
        let _ = ws_writer.close().await;
    });

    // Inbound: each WS text frame is one IRC line without CRLF — append
    // CRLF before writing into the duplex so `run_irc`'s line reader sees
    // properly terminated lines and doesn't hang waiting for `\n`.
    tokio::spawn(async move {
        tracing::info!("WS: inbound bridge task started");
        let mut frames_in: u64 = 0;
        while let Some(msg) = ws_reader.next().await {
            let mut bytes = match msg {
                Ok(WsMessage::Text(t)) => {
                    frames_in += 1;
                    let preview: String = t.chars().take(80).collect();
                    tracing::debug!(n = frames_in, len = t.len(), preview = %preview, "WS: ← text frame");
                    t.as_bytes().to_vec()
                }
                Ok(WsMessage::Binary(b)) => {
                    frames_in += 1;
                    tracing::debug!(n = frames_in, len = b.len(), "WS: ← binary frame");
                    b.to_vec()
                }
                Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) | Ok(WsMessage::Frame(_)) => {
                    continue;
                }
                Ok(WsMessage::Close(c)) => {
                    tracing::warn!(close = ?c, "WS: ← close frame");
                    break;
                }
                Err(e) => {
                    tracing::warn!("WS: read error: {e}");
                    break;
                }
            };
            if !bytes.ends_with(b"\r\n") {
                bytes.extend_from_slice(b"\r\n");
            }
            if let Err(e) = bridge_writer.write_all(&bytes).await {
                tracing::warn!("WS: bridge_write error: {e}");
                break;
            }
        }
        tracing::warn!(frames_in, "WS: inbound bridge task ending");
        let _ = bridge_writer.shutdown().await;
    });

    Ok(EstablishedConnection::WebSocket(client_side))
}

fn install_crypto_provider() {
    // Install a crypto provider for rustls.
    // ring is preferred (works on iOS); aws-lc-rs is the default on desktop.
    #[cfg(feature = "ring")]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn rustls_default_config() -> rustls::ClientConfig {
    install_crypto_provider();

    let mut root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Also load the system's native certificate store (covers CAs not in
    // Mozilla's bundle, e.g. corporate/Sectigo intermediates).
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::warn!("Errors loading native certificates: {:?}", native.errors);
    }
    let before = root_store.len();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }
    let added = root_store.len() - before;
    if added > 0 {
        tracing::debug!("Loaded {added} native root certificates");
    }

    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn rustls_insecure_config() -> rustls::ClientConfig {
    install_crypto_provider();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth()
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

async fn run_irc<R, W>(
    mut reader: R,
    mut writer: W,
    config: &ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    event_tx: mpsc::Sender<Event>,
    mut cmd_rx: mpsc::Receiver<Command>,
    echo_registry: EchoRegistry,
    caps_acked: CapsAcked,
    did_maps: DidMaps,
) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Always negotiate capabilities (message-tags, and optionally sasl)
    writer.write_all(b"CAP LS 302\r\n").await?;

    writer
        .write_all(format!("NICK {}\r\n", config.nick).as_bytes())
        .await?;
    writer
        .write_all(format!("USER {} 0 * :{}\r\n", config.user, config.realname).as_bytes())
        .await?;

    let mut sasl_in_progress = false;
    let mut registered = false;
    // Our own confirmed nick (001, self-NICK) — needed to tell which end of
    // a DM is the peer when computing dm_key.
    let mut own_nick = String::new();
    let mut nick_tries: u32 = 0;
    let mut web_token = config.web_token.clone();
    let mut authenticated_did: Option<String> = None;
    let mut pending_commands: Vec<Command> = Vec::new();
    // Task event ids already handed up. The same event arrives up to three
    // times — our own echo, the replay a channel hands a joiner, and the
    // history that joiner asks for next — and only the first is an event.
    let mut seen_act_events: SeenActEvents = SeenActEvents::default();
    // Session message-signing keypair (generated after SASL success)
    let mut msg_signing_key: Option<ed25519_dalek::SigningKey> = None;
    let mut msg_signing_did: Option<String> = None;
    // The session signing key's public half, waiting for registration to
    // finish so `MSGSIG` isn't sent into a connection that will discard it.
    let mut pending_msgsig: Option<String> = None;
    // Open `draft/multiline` batches keyed by batch id. Chunks
    // accumulate here while the batch is open; the BATCH closer drains
    // and emits a single Event::Message with the assembled body.
    let mut multiline_batches: std::collections::HashMap<String, InboundMultilineBatch> =
        std::collections::HashMap::new();
    let mut line_buf = String::new();
    let mut last_activity = tokio::time::Instant::now();
    let ping_interval = tokio::time::Duration::from_secs(60);
    let ping_timeout = tokio::time::Duration::from_secs(120);
    // Paced separately from `last_activity`: re-arming the timer off
    // `last_activity` alone busy-loops once the first keepalive fires
    // (the deadline stays in the past until inbound data arrives),
    // spamming PINGs for a full RTT — or for 60s into a dead socket.
    let mut next_ping = last_activity + ping_interval;

    loop {
        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                let n = result?;
                if n == 0 {
                    let _ = event_tx.send(Event::Disconnected { reason: "EOF".to_string() }).await;
                    break;
                }

                last_activity = tokio::time::Instant::now();
                next_ping = last_activity + ping_interval;
                let raw = line_buf.trim_end().to_string();
                let _ = event_tx.send(Event::RawLine(raw.clone())).await;

                if let Some(msg) = Message::parse(&line_buf) {
                    match msg.command.as_str() {
                        // ERR_NICKNAMEINUSE
                        "433" => {
                            // Nickname is already in use; try a variant before registration completes.
                            // Use base nick from config and append a short suffix.
                            nick_tries = nick_tries.saturating_add(1);
                            if nick_tries <= 5 {
                                let base = &config.nick;
                                let alt = if nick_tries == 1 {
                                    format!("{}1", base)
                                } else {
                                    format!("{}{}", base, nick_tries)
                                };
                                // Best-effort: attempt new nick immediately.
                                writer.write_all(format!("NICK {}\r\n", alt).as_bytes()).await?;
                            } else {
                                // Give up; let reconnect logic handle it.
                                let _ = event_tx.send(Event::Disconnected { reason: "Nick in use".to_string() }).await;
                                break;
                            }
                        }
                        "CAP" => {
                            handle_cap_response(&msg, &signer, &web_token, &mut writer, &mut sasl_in_progress, &caps_acked).await?;
                        }
                        "AUTHENTICATE" => {
                            if let Some(ref token) = web_token {
                                // Web-token SASL: server sends challenge, we respond with JSON
                                // containing method:"web-token" and the token as signature.
                                // The DID is extracted by the server from the token lookup.
                                let payload = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                                if payload == "+" || !payload.is_empty() {
                                    // For web-token, we need the DID from the token lookup.
                                    // Send a JSON response matching ChallengeResponse format.
                                    // The DID comes from the server's token store, but we need
                                    // to send *something* — use a placeholder that matches.
                                    // Actually, we need the DID. Extract from config or just
                                    // send with empty DID — server validates via token lookup.
                                    let response = serde_json::json!({
                                        "did": "", // Server fills from token lookup
                                        "method": "web-token",
                                        "signature": token,
                                    });
                                    use base64::Engine;
                                    let json_bytes = response.to_string();
                                    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_bytes.as_bytes());
                                    writer.write_all(format!("AUTHENTICATE {encoded}\r\n").as_bytes()).await?;
                                }
                            } else if let Some(ref signer) = signer {
                                handle_authenticate_challenge(&msg, signer.as_ref(), &mut writer).await?;
                            }
                        }
                        // Handle DPOP_NONCE notice during SASL — update signer nonce
                        "NOTICE" if sasl_in_progress => {
                            if let Some(text) = msg.params.last()
                                && let Some(nonce) = text.strip_prefix("DPOP_NONCE ")
                                    && let Some(ref s) = signer {
                                        s.set_dpop_nonce(nonce.trim());
                                    }
                                    // Server will re-issue AUTHENTICATE challenge next
                        }
                        // 900 RPL_LOGGEDIN — server tells us our authenticated DID
                        "900" => {
                            // :server 900 nick :You are now logged in as did:plc:...
                            if let Some(text) = msg.params.last()
                                && let Some(did) = text.split("as ").last() {
                                    let did = did.trim().to_string();
                                    if did.starts_with("did:") {
                                        authenticated_did = Some(did);
                                    }
                                }
                        }
                        "903" => {
                            sasl_in_progress = false;
                            let did = authenticated_did.take()
                                .or_else(|| signer.as_ref().map(|s| s.did().to_string()))
                                .unwrap_or_default();
                            // Only where the key can be used: a server that
                            // never negotiated the cap cannot verify a client
                            // document, so registering a key with it files a
                            // public key it will never read — and the command
                            // itself is one an older server has no reason to
                            // know. Cap negotiation is settled by now.
                            let server_verifies_documents =
                                caps_acked.lock().acked.contains(MSGSIG_CAP);
                            if !did.is_empty() {
                                let _ = event_tx.send(Event::Authenticated { did: did.clone() }).await;
                            }
                            if !did.is_empty() && server_verifies_documents {
                                // Generate session message-signing keypair
                                let key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
                                let pubkey_bytes = key.verifying_key().as_bytes().to_vec();
                                use base64::Engine;
                                let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pubkey_bytes);
                                msg_signing_key = Some(key);
                                msg_signing_did = Some(did);
                                // Registered on 001, not here: MSGSIG before
                                // registration completes is dropped by the
                                // server (`if !conn.registered { continue }`),
                                // which left the key unregistered and every
                                // "client-signed" message silently
                                // server-signed instead.
                                pending_msgsig = Some(pubkey_b64);
                            }
                            web_token = None;
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "904" => {
                            sasl_in_progress = false;
                            let reason = msg.params.get(1).cloned().unwrap_or_else(|| "Unknown".to_string());
                            // eprintln!("  SASL authentication FAILED: {reason}");
                            let _ = event_tx.send(Event::AuthFailed { reason }).await;
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "BATCH" => {
                            if let Some(ref_id) = msg.params.first() {
                                if let Some(id) = ref_id.strip_prefix('+') {
                                    let batch_type = msg.params.get(1).cloned().unwrap_or_default();
                                    let target = msg.params.get(2).cloned().unwrap_or_default();
                                    if batch_type == "draft/multiline" {
                                        // Capture opener metadata so the
                                        // assembled message inherits the
                                        // right identity (msgid, time,
                                        // sender, client-only tags).
                                        let from = msg
                                            .prefix
                                            .as_deref()
                                            .and_then(|p| p.split('!').next())
                                            .unwrap_or("")
                                            .to_string();
                                        let mut opener_tags = msg.tags.clone();
                                        // The `batch` tag on the opener
                                        // is the PARENT batch (nesting).
                                        let parent_batch_id =
                                            opener_tags.remove("batch");
                                        multiline_batches.insert(
                                            id.to_string(),
                                            InboundMultilineBatch {
                                                target: target.clone(),
                                                from,
                                                opener_tags,
                                                lines: Vec::new(),
                                                parent_batch_id,
                                            },
                                        );
                                        // Suppress BatchStart for multiline
                                        // — the consumer gets a single
                                        // Message at close time instead.
                                    } else {
                                        let _ = event_tx.send(Event::BatchStart {
                                            id: id.to_string(),
                                            batch_type,
                                            target,
                                        }).await;
                                    }
                                } else if let Some(id) = ref_id.strip_prefix('-') {
                                    if let Some(batch) = multiline_batches.remove(id) {
                                        let dm_key = dm_key_for(
                                            &did_maps,
                                            &own_nick,
                                            &batch.from,
                                            &batch.target,
                                        );
                                        dispatch_assembled_multiline(&event_tx, batch, dm_key).await;
                                    } else {
                                        let _ = event_tx.send(Event::BatchEnd { id: id.to_string() }).await;
                                    }
                                }
                            }
                        }
                        "001" => {
                            let nick = msg.params.first().cloned().unwrap_or_default();
                            own_nick = nick.clone();
                            let _ = event_tx.send(Event::Registered { nick }).await;
                            registered = true;
                            // Register the session's message-signing key now
                            // that the server will accept it — before any
                            // queued message goes out, so nothing is sent
                            // with a signature the server can't yet check.
                            if let Some(pubkey_b64) = pending_msgsig.take() {
                                writer
                                    .write_all(format!("MSGSIG {pubkey_b64}\r\n").as_bytes())
                                    .await?;
                            }
                            // Flush any commands that were queued before registration
                            let verifies = caps_acked.lock().acked.contains(MSGSIG_CAP);
                            for cmd in pending_commands.drain(..) {
                                execute_command(&mut writer, cmd, &msg_signing_key, &msg_signing_did, verifies).await?;
                            }
                        }
                        "353" => {
                            if msg.params.len() >= 4 {
                                let channel = msg.params[2].clone();
                                let nicks: Vec<String> = msg.params[3].split_whitespace().map(|s| s.to_string()).collect();
                                let _ = event_tx.send(Event::Names { channel, nicks }).await;
                            }
                        }
                        "366" => {
                            // RPL_ENDOFNAMES
                            if msg.params.len() >= 2 {
                                let channel = msg.params[1].clone();
                                let _ = event_tx.send(Event::NamesEnd { channel }).await;
                            }
                        }
                        "PING" => {
                            let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                            writer.write_all(format!("PONG :{token}\r\n").as_bytes()).await?;
                        }
                        "JOIN" => {
                            let channel = msg.params.first().cloned().unwrap_or_default();
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            // extended-join: `JOIN <chan> <account> :<realname>`.
                            // account is "*" when the joiner isn't authenticated.
                            let account = msg.params.get(1)
                                .filter(|a| !a.is_empty() && a.as_str() != "*")
                                .cloned();
                            if let Some(did) = account.as_deref()
                                && crate::address::is_did(did)
                                && did_maps.lock().learn(&nick, did)
                            {
                                let _ = event_tx
                                    .send(Event::MemberDid { nick: nick.clone(), did: did.to_string() })
                                    .await;
                            }
                            let _ = event_tx.send(Event::Joined { channel, nick, account }).await;
                        }
                        "PART" => {
                            let channel = msg.params.first().cloned().unwrap_or_default();
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let _ = event_tx.send(Event::Parted { channel, nick }).await;
                        }
                        "NICK" => {
                            let old_nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let new_nick = msg.params.first().cloned().unwrap_or_default();
                            if !old_nick.is_empty() && !new_nick.is_empty() {
                                if old_nick.eq_ignore_ascii_case(&own_nick) {
                                    own_nick = new_nick.clone();
                                }
                                did_maps.lock().rename(&old_nick, &new_nick);
                                let _ = event_tx.send(Event::NickChanged { old_nick, new_nick }).await;
                            }
                        }
                        // MODE change
                        "MODE" => {
                            if msg.params.len() >= 2 {
                                let target = &msg.params[0];
                                if target.starts_with('#') || target.starts_with('&') {
                                    let mode = msg.params[1].clone();
                                    let arg = msg.params.get(2).cloned();
                                    let set_by = msg.prefix.as_deref()
                                        .and_then(|p| p.split('!').next())
                                        .unwrap_or("server")
                                        .to_string();
                                    let _ = event_tx.send(Event::ModeChanged {
                                        channel: target.clone(),
                                        mode,
                                        arg,
                                        set_by,
                                    }).await;
                                }
                            }
                        }
                        // KICK
                        "KICK" => {
                            if msg.params.len() >= 2 {
                                let channel = msg.params[0].clone();
                                let kicked_nick = msg.params[1].clone();
                                let reason = msg.params.get(2).cloned().unwrap_or_default();
                                let by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("server")
                                    .to_string();
                                let _ = event_tx.send(Event::Kicked {
                                    channel,
                                    nick: kicked_nick,
                                    by,
                                    reason,
                                }).await;
                            }
                        }
                        // INVITE
                        "INVITE" => {
                            if msg.params.len() >= 2 {
                                let channel = msg.params[1].clone();
                                let by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("someone")
                                    .to_string();
                                let _ = event_tx.send(Event::Invited { channel, by }).await;
                            }
                        }
                        // AWAY (away-notify broadcast from shared channels)
                        "AWAY" => {
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let away_msg = msg.params.first().cloned();
                            let _ = event_tx.send(Event::AwayChanged { nick, away_msg }).await;
                        }
                        // MARKREAD (draft/read-marker) — reply to our own
                        // get/set, or a push from another of our devices.
                        // Format: `MARKREAD <target> timestamp=<iso>` or
                        // `MARKREAD <target> *`.
                        "MARKREAD" => {
                            if let Some(target) = msg.params.first().cloned() {
                                let timestamp = msg.params.get(1).and_then(|v| {
                                    if v == "*" {
                                        None
                                    } else {
                                        v.strip_prefix("timestamp=").map(|s| s.to_string())
                                    }
                                });
                                let _ = event_tx.send(Event::ReadMarker { target, timestamp }).await;
                            }
                        }
                        // TOPIC (live change from another user)
                        "TOPIC" => {
                            if let Some(channel) = msg.params.first() {
                                let topic = msg.params.get(1).cloned().unwrap_or_default();
                                let set_by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .map(|s| s.to_string());
                                let _ = event_tx.send(Event::TopicChanged {
                                    channel: channel.clone(),
                                    topic,
                                    set_by,
                                }).await;
                            }
                        }
                        // RPL_TOPIC (on join or TOPIC query)
                        "332" => {
                            if msg.params.len() >= 3 {
                                let channel = msg.params[1].clone();
                                let topic = msg.params[2].clone();
                                let _ = event_tx.send(Event::TopicChanged {
                                    channel,
                                    topic,
                                    set_by: None,
                                }).await;
                            }
                        }
                        "331" => {
                            // RPL_NOTOPIC — no topic set, ignore or clear
                        }
                        "333" => {
                            // RPL_TOPICWHOTIME — ignore for now (info only)
                        }
                        // WHOIS numerics
                        "311" => {
                            // RPL_WHOISUSER: <nick> <user> <host> * :<realname>
                            if msg.params.len() >= 5 {
                                let nick = msg.params[1].clone();
                                let user = &msg.params[2];
                                let host = &msg.params[3];
                                let realname = &msg.params[4]; // skip the "*" at [3] — it's actually nick user host * :realname
                                let info = format!("{nick} is {user}@{host} ({realname})");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "312" => {
                            // RPL_WHOISSERVER: <nick> <server> :<server info>
                            if msg.params.len() >= 4 {
                                let nick = msg.params[1].clone();
                                let server = &msg.params[2];
                                let info_text = &msg.params[3];
                                let info = format!("{nick} using {server} ({info_text})");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "319" => {
                            // RPL_WHOISCHANNELS: <nick> :<channels>
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let info = format!("{nick} on {}", msg.params[2]);
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "330" => {
                            // RPL_WHOISACCOUNT: <nick> <account> :is logged in as
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let account = &msg.params[2];
                                if crate::address::is_did(account)
                                    && did_maps.lock().learn(&nick, account)
                                {
                                    let _ = event_tx
                                        .send(Event::MemberDid {
                                            nick: nick.clone(),
                                            did: account.clone(),
                                        })
                                        .await;
                                }
                                let label = msg.params.get(3).map(|s| s.as_str()).unwrap_or("is authenticated as");
                                let info = format!("{nick} {label} {account}");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "318" => {
                            // RPL_ENDOFWHOIS — the server is done. Nothing
                            // more is coming, so a caller waiting to hear
                            // whether this nick has an account has its answer.
                            if msg.params.len() >= 2 {
                                let nick = msg.params[1].clone();
                                let _ = event_tx.send(Event::WhoisEnd { nick }).await;
                            }
                        }
                        "401" => {
                            // ERR_NOSUCHNICK — also the end of a WHOIS, and
                            // the only end some servers send for a nick that
                            // isn't there.
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let _ = event_tx.send(Event::WhoisReply {
                                    nick: nick.clone(),
                                    info: format!("{nick}: No such nick"),
                                }).await;
                                let _ = event_tx.send(Event::WhoisEnd { nick }).await;
                            }
                        }
                        "QUIT" => {
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let reason = msg.params.first().cloned().unwrap_or_default();
                            did_maps.lock().forget_nick(&nick);
                            let _ = event_tx.send(Event::UserQuit { nick, reason }).await;
                        }
                        "PRIVMSG" | "NOTICE" => {
                            if msg.params.len() >= 2 {
                                let prefix = msg.prefix.as_deref().unwrap_or("");
                                let is_server_notice = msg.command == "NOTICE"
                                    && !prefix.contains('!');
                                if is_server_notice {
                                    // Server NOTICE (no hostmask in prefix) → ServerNotice
                                    let text = msg.params[1].clone();
                                    let _ = event_tx.send(Event::ServerNotice { text }).await;
                                } else {
                                    // If this PRIVMSG is a chunk of an
                                    // open `draft/multiline` batch,
                                    // accumulate it raw and defer the
                                    // Event::Message emission until the
                                    // closer fires. Decoding per-chunk
                                    // would corrupt ciphertext-chunked
                                    // bodies (each fragment is part of
                                    // one AES-GCM blob).
                                    if let Some(batch_id) = msg.tags.get("batch")
                                        && let Some(batch) =
                                            multiline_batches.get_mut(batch_id)
                                    {
                                        batch.lines.push(MultilineChunk {
                                            body: msg.params[1].clone(),
                                            concat: msg
                                                .tags
                                                .contains_key("draft/multiline-concat"),
                                        });
                                        line_buf.clear();
                                        continue;
                                    }

                                    let from = prefix.split('!').next()
                                        .unwrap_or("")
                                        .to_string();
                                    let target = msg.params[0].clone();
                                    let mut text = msg.params[1].clone();
                                    let tags = msg.tags.clone();

                                    // Legacy `+freeq.at/multiline`: pre-spec
                                    // wire encoded `\n` as the literal two
                                    // chars `\\n`. New senders use the BATCH
                                    // path; the tag remains in use by older
                                    // senders. Normalize here so consumers
                                    // always see real `\n`.
                                    if tags.contains_key("+freeq.at/multiline") {
                                        text = text.replace("\\n", "\n");
                                    }

                                    // Check for echo-nonce match (for send_and_await_echo)
                                    if let Some(nonce) = tags.get("+freeq.at/echo-nonce")
                                        && let Some(tx) = echo_registry.lock().remove(nonce)
                                        && let Some(msgid) = tags.get("msgid")
                                    {
                                        let _ = tx.send(msgid.clone());
                                    }

                                    // Learn the sender's DID from the account
                                    // tag (a cold first DM would otherwise key
                                    // by nick until too late) and announce a
                                    // new binding so consumers can merge.
                                    //
                                    // Learned from whatever venue the message
                                    // arrived through. The server stamps the
                                    // tag for any sender holding an account, so
                                    // a channel message carries the same
                                    // binding a DM does — and for a session
                                    // that joined after the sender was already
                                    // there, it is the only one it will ever
                                    // get: it saw no extended JOIN, and NAMES
                                    // carries no DIDs.
                                    if !from.eq_ignore_ascii_case(&own_nick)
                                        && let Some(did) = tags.get("account")
                                        && crate::address::is_did(did)
                                        && did_maps.lock().learn(&from, did)
                                    {
                                        let _ = event_tx
                                            .send(Event::MemberDid {
                                                nick: from.clone(),
                                                did: did.clone(),
                                            })
                                            .await;
                                    }
                                    let dm_key =
                                        dm_key_for(&did_maps, &own_nick, &from, &target);
                                    let _ = event_tx.send(Event::Message { from, target, text, tags, dm_key }).await;
                                }
                            }
                        }
                        "TAGMSG" => {
                            if !msg.params.is_empty() {
                                let from = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("")
                                    .to_string();
                                let target = msg.params[0].clone();
                                // A TAGMSG carries the same server-stamped
                                // account tag a PRIVMSG does — a delete is
                                // relayed with one — so it names its sender
                                // just as well. The JS SDK learns here too;
                                // leaving it out would mean a peer known to
                                // one client and nameless to the other.
                                if !from.eq_ignore_ascii_case(&own_nick)
                                    && let Some(did) = msg.tags.get("account")
                                    && crate::address::is_did(did)
                                    && did_maps.lock().learn(&from, did)
                                {
                                    let _ = event_tx
                                        .send(Event::MemberDid {
                                            nick: from.clone(),
                                            did: did.clone(),
                                        })
                                        .await;
                                }
                                let dm_key = dm_key_for(&did_maps, &own_nick, &from, &target);
                                // A task event is handed up as its own event
                                // as well as the raw TAGMSG, the way a
                                // coordination TAGMSG is — once per event id.
                                if let Some(act) = crate::act::parse_event(
                                    msg.tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                                ) && seen_act_events.first_sighting(&act.event_id)
                                {
                                    let _ = event_tx
                                        .send(Event::Act {
                                            from: from.clone(),
                                            target: target.clone(),
                                            kind: act.kind,
                                            verb: act.verb,
                                            did: act.did,
                                            event_id: act.event_id,
                                            task_id: act.task_id,
                                            fields: act.fields,
                                            sig_tag: act.sig_tag,
                                            replayed: act.replayed,
                                            dm_key: dm_key.clone(),
                                        })
                                        .await;
                                }
                                let _ = event_tx.send(Event::TagMsg { from, target, tags: msg.tags.clone(), dm_key }).await;
                            }
                        }
                        "CHATHISTORY" => {
                            // CHATHISTORY TARGETS <nick> — DM conversation list
                            #[allow(clippy::collapsible_if)]
                            if msg.params.first().map(|s| s.as_str()) == Some("TARGETS") {
                                if let Some(nick) = msg.params.get(1) {
                                    let timestamp = msg.tags.get("time").cloned();
                                    // The server names the conversation's
                                    // stable identity in the partner-did tag;
                                    // learn display-only (the nick may be
                                    // historical — never addressing-grade).
                                    let partner_did = msg
                                        .tags
                                        .get("freeq.at/partner-did")
                                        .filter(|d| crate::address::is_did(d))
                                        .cloned();
                                    if let Some(ref did) = partner_did {
                                        did_maps.lock().learn_display(did, nick);
                                    }
                                    let _ = event_tx
                                        .send(Event::ChatHistoryTarget {
                                            nick: nick.clone(),
                                            timestamp,
                                            partner_did,
                                        })
                                        .await;
                                }
                            }
                        }
                        "FAIL" => {
                            // IRCv3 FAIL command — emit as ServerNotice
                            let text = msg.params.join(" ");
                            let _ = event_tx.send(Event::ServerNotice { text }).await;
                        }
                        _ => {
                            // Emit server error numerics (4xx, 5xx, 6xx, 9xx),
                            // MOTD lines (372/375/376), and unrecognized commands
                            // as ServerNotice so the UI can display them.
                            if let Ok(num) = msg.command.parse::<u16>() {
                                if (400..700).contains(&num) || (900..1000).contains(&num) {
                                    // Skip our nick (param[0]) and join the rest
                                    let text = if msg.params.len() > 1 {
                                        msg.params[1..].join(" ")
                                    } else {
                                        msg.params.join(" ")
                                    };
                                    let _ = event_tx.send(Event::ServerNotice { text }).await;
                                } else if num == 372 {
                                    // MOTD body line — strip "- " prefix
                                    let text = if msg.params.len() > 1 {
                                        let body = msg.params[1..].join(" ");
                                        let stripped = body.strip_prefix("- ").unwrap_or(&body);
                                        format!("MOTD:{}", stripped)
                                    } else {
                                        "MOTD:".to_string()
                                    };
                                    let _ = event_tx.send(Event::ServerNotice { text }).await;
                                } else if num == 375 {
                                    let _ = event_tx.send(Event::ServerNotice { text: "MOTD:START".to_string() }).await;
                                } else if num == 376 {
                                    let _ = event_tx.send(Event::ServerNotice { text: "MOTD:END".to_string() }).await;
                                }
                            }
                        }
                    }
                }

                line_buf.clear();
            }
            Some(cmd) = cmd_rx.recv() => {
                if registered || matches!(cmd, Command::Quit(_)) {
                    let verifies = caps_acked.lock().acked.contains(MSGSIG_CAP);
                    execute_command(&mut writer, cmd, &msg_signing_key, &msg_signing_did, verifies).await?;
                    if !registered {
                        break; // Quit before registration
                    }
                } else {
                    // Queue until registered — commands silently wait
                    pending_commands.push(cmd);
                }
            }
            // Periodic client-to-server PING and timeout detection
            _ = tokio::time::sleep_until(next_ping) => {
                if last_activity.elapsed() > ping_timeout {
                    let _ = event_tx.send(Event::Disconnected { reason: "Ping timeout".to_string() }).await;
                    break;
                }
                writer.write_all(b"PING :keepalive\r\n").await?;
                next_ping = tokio::time::Instant::now() + ping_interval;
            }
        }
    }

    Ok(())
}

/// Assemble a closed `draft/multiline` batch into a single
/// `Event::Message` per the spec's concat rules — a chunk with
/// `draft/multiline-concat` joins its predecessor with no separator;
/// otherwise the join is `\n`. The opener's tags become the assembled
/// message's tags (msgid, time, sender's account, etc.).
async fn dispatch_assembled_multiline(
    event_tx: &mpsc::Sender<Event>,
    batch: InboundMultilineBatch,
    dm_key: Option<String>,
) {
    let mut text = String::new();
    for (i, line) in batch.lines.iter().enumerate() {
        if i > 0 && !line.concat {
            text.push('\n');
        }
        text.push_str(&line.body);
    }
    let mut tags = batch.opener_tags;
    if let Some(parent_batch_id) = batch.parent_batch_id {
        tags.insert("batch".to_string(), parent_batch_id);
    }
    let _ = event_tx
        .send(Event::Message {
            from: batch.from,
            target: batch.target,
            text,
            tags,
            dm_key,
        })
        .await;
    // Nested-batch parent (e.g. multiline inside CHATHISTORY) is
    // exposed to the consumer via the `batch` tag so UI layers can
    // attach the assembled message to the outer batch.
}

/// How long a task event's id is remembered so the same event is not handed up
/// twice.
///
/// Generous on purpose: the duplicate this exists to swallow is a joiner's
/// replay followed by the history it asks for, and a catch-up over a slow link
/// can put minutes between the two sightings of one event.
const ACT_EVENT_DEDUPE: std::time::Duration = std::time::Duration::from_secs(600);

/// The task event ids this connection has already handed up, and when.
#[derive(Default)]
struct SeenActEvents {
    seen: HashMap<String, std::time::Instant>,
}

impl SeenActEvents {
    /// Whether this id is new, recording it if so. Old entries are swept when
    /// the map grows rather than on a timer: nothing here is worth a task.
    fn first_sighting(&mut self, event_id: &str) -> bool {
        let now = std::time::Instant::now();
        if let Some(seen) = self.seen.get(event_id)
            && now.duration_since(*seen) < ACT_EVENT_DEDUPE
        {
            return false;
        }
        self.seen.insert(event_id.to_string(), now);
        if self.seen.len() > 4096 {
            self.seen
                .retain(|_, t| now.duration_since(*t) < ACT_EVENT_DEDUPE);
        }
        true
    }
}

/// The capability a server advertises to say it verifies the chat signing
/// document — see [`crate::chatsig`] for what that document is.
///
/// A signature is only worth sending to a server that checks it. Against one
/// that doesn't, the signature is stripped and replaced by the server's own
/// (the pre-document behaviour), and the event id we minted is ignored while
/// its tag leaks onward — so signing there costs bytes and buys nothing, and
/// worse, produces a lock badge no client should trust. Gating on the cap makes
/// the client rollout self-coordinating per server: no deploy lockstep, no
/// flag day.
pub const MSGSIG_CAP: &str = "freeq.at/msgsig";

/// The capability a client must ack to be sent task events.
///
/// The server delivers an act TAGMSG only to sessions that asked for it, so a
/// client that renders task cards and never asks receives nothing at all.
pub const ACT_CAP: &str = "freeq.at/act";

/// Put a chat signature (and the event id it covers) on an outgoing message's
/// tags, when this session has a signing key and the venue is knowable.
///
/// The document is `freeq_sdk::chatsig`'s: the sender's DID, a **signer-minted**
/// event id, the normalized venue, a hash of the wire body, plus the reply,
/// edit and coordination tags that are present. Signing over an id we mint —
/// instead of the wall clock the retired canonical used — is what lets any
/// receiver rebuild the exact signed bytes: the id travels as `msgid`, the
/// clock never travelled at all.
///
/// Nothing is added when the venue can't be determined (a bare-nick DM whose
/// peer DID we haven't learned): sending unsigned is honest, while signing a
/// venue no verifier would rebuild produces a signature that reads as
/// tampering.
/// Nothing is signed and no id is minted against a server that never
/// negotiated [`MSGSIG_CAP`] — see that constant for why.
fn sign_outgoing(
    tags: &mut std::collections::HashMap<String, String>,
    signing_key: &Option<ed25519_dalek::SigningKey>,
    signing_did: &Option<String>,
    target: &str,
    body: &str,
    server_verifies_documents: bool,
) {
    if !server_verifies_documents {
        return;
    }
    let (Some(key), Some(did)) = (signing_key, signing_did) else {
        return;
    };
    let Some(venue) = crate::chatsig::venue_for_target(target, did) else {
        tracing::debug!(
            target,
            "no signable venue for this target — sending unsigned"
        );
        return;
    };

    let event_id = crate::chatsig::new_event_id();
    let mut doc = crate::chatsig::ChatDoc::message(did, &event_id, &venue, body);
    // References name root msgids, which are the only ids a client is ever
    // given: a message keeps its id through every revision.
    let reply = tags
        .get("+reply")
        .or_else(|| tags.get("+draft/reply"))
        .cloned();
    if let Some(ref reply) = reply {
        doc = doc.with_reply(reply);
    }
    let edit = tags.get("+draft/edit").cloned();
    if let Some(ref edit) = edit {
        doc = doc.with_edit(edit);
    }
    let coord: Vec<(String, String)> = tags.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let doc = doc.with_coord(coord.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    tags.insert(crate::chatsig::EVENT_ID_TAG.to_string(), event_id.clone());
    tags.insert(crate::sigtag::SIG_TAG.to_string(), doc.sign(key));
}

/// The mutation a TAGMSG's tags describe: the kind, the **root** msgid it acts
/// on, and — for reactions — the emoji.
///
/// The same three tag shapes the server reads on the receive side, so what a
/// sender signs and what a verifier rebuilds cannot drift: a delete carries
/// its subject as the value of `+draft/delete`, a reaction carries the emoji
/// in `+react` (or `+freeq.at/unreact`) and the subject in `+reply`.
///
/// `None` for every other TAGMSG — typing, AV signalling, presence. Those are
/// ephemera: nothing durable is asserted under a user's name, so there is
/// nothing for a signature to be evidence of.
fn mutation_in(
    tags: &std::collections::HashMap<String, String>,
) -> Option<(crate::chatsig::Mutation, String, Option<String>)> {
    use crate::chatsig::Mutation;
    let get = |a: &str, b: &str| tags.get(a).or_else(|| tags.get(b)).cloned();
    let subject = || get("+reply", "+draft/reply");
    if let Some(subject) = get("+draft/delete", "+delete") {
        return Some((Mutation::Delete, subject, None));
    }
    if let Some(emoji) = get("+react", "+draft/react") {
        return Some((Mutation::React, subject()?, Some(emoji)));
    }
    if let Some(emoji) = tags.get("+freeq.at/unreact").cloned() {
        return Some((Mutation::Unreact, subject()?, Some(emoji)));
    }
    None
}

/// Sign an outgoing mutation — a delete, a reaction added or removed — and put
/// the event id the signature covers on its tags.
///
/// A mutation is durable state asserted under a user's name: it retracts a
/// message or attaches a reaction that others will see and that history will
/// keep. Signing it is what lets the server act on a *proven* actor rather
/// than on a nick, and what lets a receiving server check the claim for
/// itself instead of taking the relaying peer's word.
///
/// Same three refusals as a message: no key, no venue (a bare-nick DM has no
/// reproducible venue — send unsigned rather than sign a guess), and nothing
/// at all against a server that never negotiated [`MSGSIG_CAP`].
fn sign_mutation_outgoing(
    tags: &mut std::collections::HashMap<String, String>,
    signing_key: &Option<ed25519_dalek::SigningKey>,
    signing_did: &Option<String>,
    target: &str,
    server_verifies_documents: bool,
) {
    if !server_verifies_documents {
        return;
    }
    let (Some(key), Some(did)) = (signing_key, signing_did) else {
        return;
    };
    let Some((kind, subject, emoji)) = mutation_in(tags) else {
        return;
    };
    let Some(venue) = crate::chatsig::venue_for_target(target, did) else {
        tracing::debug!(
            target,
            "no signable venue for this target — sending the mutation unsigned"
        );
        return;
    };

    let event_id = crate::chatsig::new_event_id();
    let mut doc = crate::chatsig::ChatDoc::mutation(kind, did, &event_id, &venue, &subject);
    if let Some(ref emoji) = emoji {
        doc = doc.with_emoji(emoji);
    }
    let sig = doc.sign(key);
    tags.insert(crate::chatsig::EVENT_ID_TAG.to_string(), event_id);
    tags.insert(crate::sigtag::SIG_TAG.to_string(), sig);
}

/// The id an unsigned coordination event is filed under: the format the
/// emitter has always minted, kept so a server that never offered the cap
/// receives exactly what it always did.
fn legacy_event_id() -> String {
    format!(
        "{:016x}{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        rand::random::<u64>(),
    )
}

/// Sign a coordination event's own document, returning the `+freeq.at/sig`
/// value.
///
/// `None` — and the caller falls back to the legacy `msgid` tag — under the
/// same three refusals as everything else: a server that doesn't verify
/// documents, no key, and no venue a verifier could rebuild.
#[allow(clippy::too_many_arguments)]
fn sign_coordination_outgoing(
    signing_key: &Option<ed25519_dalek::SigningKey>,
    signing_did: &Option<String>,
    channel: &str,
    event_id: &str,
    event_type: &str,
    payload: &str,
    ref_id: Option<&str>,
    evidence_type: Option<&str>,
    server_verifies_documents: bool,
) -> Option<String> {
    if !server_verifies_documents {
        return None;
    }
    let (key, did) = (signing_key.as_ref()?, signing_did.as_ref()?);
    let venue = crate::chatsig::venue_for_target(channel, did).or_else(|| {
        tracing::debug!(
            channel,
            "no signable venue for this target — sending the event unsigned"
        );
        None
    })?;
    let mut doc = crate::chatsig::ChatDoc::coordination(did, event_id, &venue, event_type)
        .with_payload(payload);
    if let Some(ref_id) = ref_id {
        doc = doc.with_ref(ref_id);
    }
    if let Some(evidence_type) = evidence_type {
        doc = doc.with_evidence(evidence_type);
    }
    Some(doc.sign(key))
}

/// What a caller is told when a task event cannot be signed.
///
/// One sentence for all three causes — no key, no DID, no venue a verifier
/// could rebuild — because the answer is the same in each case and the
/// TypeScript SDK's `sendAct` already words it this way.
const ACT_UNSIGNABLE: &str = "a task event must be signed: authenticate, register a signing key, \
                              and address a channel or a DID";

/// Put a task event on the wire: the signed TAGMSG that *is* the event, then
/// the plain-text companion that renders it for people.
///
/// The same paired send the coordination emitter does, and for the same reason
/// — two documents, each signing its own id. The companion links back with
/// `+freeq.at/ref`, which is on chat's covered list; an `act-` name there would
/// sit outside every signature, because those belong to task messages alone.
/// It names the action, which for an opener is the opener itself.
///
/// Never falls back to unsigned: the refusal goes to the caller instead. The
/// outer `Result` is the wire's; the inner one is the caller's.
#[allow(clippy::too_many_arguments)]
async fn send_act_event<W: AsyncWrite + Unpin>(
    writer: &mut W,
    target: &str,
    event_id: &str,
    mut tags: std::collections::HashMap<String, String>,
    human_text: &str,
    signing_key: &Option<ed25519_dalek::SigningKey>,
    signing_did: &Option<String>,
    server_verifies_documents: bool,
) -> Result<Result<()>> {
    let (Some(key), Some(did)) = (signing_key, signing_did) else {
        return Ok(Err(anyhow::anyhow!(ACT_UNSIGNABLE)));
    };
    let Some(venue) = crate::chatsig::venue_for_target(target, did) else {
        return Ok(Err(anyhow::anyhow!(ACT_UNSIGNABLE)));
    };
    let sig = match crate::act::sign_act(
        tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        &venue,
        event_id,
        key,
    ) {
        Ok(sig) => sig,
        Err(e) => return Ok(Err(anyhow::Error::new(e))),
    };
    // The action this event is about: the one it names, or itself when it
    // names none — an opener's own id is the action's for the rest of its life.
    let task = tags
        .get("+freeq.at/act-id")
        .cloned()
        .unwrap_or_else(|| event_id.to_string());
    tags.insert(
        crate::chatsig::EVENT_ID_TAG.to_string(),
        event_id.to_string(),
    );
    tags.insert(crate::sigtag::SIG_TAG.to_string(), sig);
    let tagmsg = crate::irc::Message {
        tags,
        prefix: None,
        command: "TAGMSG".to_string(),
        params: vec![target.to_string()],
    };
    writer.write_all(format!("{tagmsg}\r\n").as_bytes()).await?;

    // The companion is an ordinary message signing its own id, carrying only
    // the reference that joins it to the action. A caller who asked for no
    // line gets none: the event is already on the wire.
    if !human_text.is_empty() {
        let mut companion = std::collections::HashMap::from([("+freeq.at/ref".to_string(), task)]);
        sign_outgoing(
            &mut companion,
            signing_key,
            signing_did,
            target,
            human_text,
            server_verifies_documents,
        );
        let privmsg = crate::irc::Message {
            tags: companion,
            prefix: None,
            command: "PRIVMSG".to_string(),
            params: vec![target.to_string(), human_text.to_string()],
        };
        writer
            .write_all(format!("{privmsg}\r\n").as_bytes())
            .await?;
    }
    Ok(Ok(()))
}

/// Execute a single IRC command on the wire.
///
/// If `signing_key` and `signing_did` are set **and** the server negotiated
/// [`MSGSIG_CAP`], a PRIVMSG gets a `+freeq.at/sig` tag and the event id it
/// covers.
async fn execute_command<W: AsyncWrite + Unpin>(
    writer: &mut W,
    cmd: Command,
    signing_key: &Option<ed25519_dalek::SigningKey>,
    signing_did: &Option<String>,
    server_verifies_documents: bool,
) -> Result<()> {
    match cmd {
        Command::Join(channel) => {
            writer
                .write_all(format!("JOIN {channel}\r\n").as_bytes())
                .await?;
        }
        Command::Privmsg {
            target,
            text,
            mut tags,
        } => {
            sign_outgoing(
                &mut tags,
                signing_key,
                signing_did,
                &target,
                &text,
                server_verifies_documents,
            );
            if tags.is_empty() {
                writer
                    .write_all(format!("PRIVMSG {target} :{text}\r\n").as_bytes())
                    .await?;
            } else {
                let msg = crate::irc::Message {
                    tags,
                    prefix: None,
                    command: "PRIVMSG".to_string(),
                    params: vec![target, text],
                };
                writer.write_all(format!("{msg}\r\n").as_bytes()).await?;
            }
        }
        Command::SendMultiline {
            target,
            chunks,
            mut opener_tags,
        } => {
            // Mint a batch id with a random suffix; collision-free
            // within a single connection at one nanosecond + random id.
            let batch_id = format!(
                "ml{:x}{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u32,
                rand::random::<u32>(),
            );
            // Reassemble the body per concat rules and sign it. The
            // signature rides on the BATCH opener — the server's
            // signature verification reads `+freeq.at/sig` from the
            // assembled message's tags (which are the opener tags
            // after multiline dispatch), so per-chunk sigs would not
            // verify against the canonical `{did}\0{target}\0{body}\0{ts}`.
            // The body the *server* will assemble — the bytes the document's
            // hash covers. Per-chunk signatures would cover something no
            // receiver ever holds.
            let mut body = String::new();
            for (i, chunk) in chunks.iter().enumerate() {
                if i > 0 && !chunk.concat {
                    body.push('\n');
                }
                body.push_str(&chunk.body);
            }
            sign_outgoing(
                &mut opener_tags,
                signing_key,
                signing_did,
                &target,
                &body,
                server_verifies_documents,
            );
            let opener_tags_str = if opener_tags.is_empty() {
                String::new()
            } else {
                let s = opener_tags
                    .iter()
                    .map(|(k, v)| {
                        if v.is_empty() {
                            k.clone()
                        } else {
                            format!("{k}={v}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                format!("@{s} ")
            };
            writer
                .write_all(
                    format!("{opener_tags_str}BATCH +{batch_id} draft/multiline {target}\r\n")
                        .as_bytes(),
                )
                .await?;
            // Per-chunk PRIVMSGs carry `batch=<id>` and, if applicable,
            // `draft/multiline-concat`. Sigs are on the opener, not here.
            for chunk in &chunks {
                let mut chunk_tags = format!("batch={batch_id}");
                if chunk.concat {
                    chunk_tags.push_str(";draft/multiline-concat");
                }
                writer
                    .write_all(
                        format!("@{chunk_tags} PRIVMSG {target} :{}\r\n", chunk.body).as_bytes(),
                    )
                    .await?;
            }
            writer
                .write_all(format!("BATCH -{batch_id}\r\n").as_bytes())
                .await?;
        }
        Command::Tagmsg { target, mut tags } => {
            sign_mutation_outgoing(
                &mut tags,
                signing_key,
                signing_did,
                &target,
                server_verifies_documents,
            );
            let msg = crate::irc::Message {
                tags,
                prefix: None,
                command: "TAGMSG".to_string(),
                params: vec![target],
            };
            writer.write_all(format!("{msg}\r\n").as_bytes()).await?;
        }
        Command::CoordinationEvent {
            channel,
            event_id,
            event_type,
            payload,
            ref_id,
            evidence_type,
            human_text,
        } => {
            let signature = sign_coordination_outgoing(
                signing_key,
                signing_did,
                &channel,
                &event_id,
                &event_type,
                &payload,
                ref_id.as_deref(),
                evidence_type.as_deref(),
                server_verifies_documents,
            );
            let Some(signature) = signature else {
                // Nothing here can be vouched for, so send what a pre-signing
                // client sent, verbatim: the server reads the id off `msgid`,
                // and the id the caller holds stays the id on file.
                let mut tags = format!(
                    "+freeq.at/event={event_type};msgid={event_id};+freeq.at/payload={payload}"
                );
                if let Some(ref rid) = ref_id {
                    tags.push_str(&format!(";+freeq.at/ref={rid}"));
                }
                if let Some(ref evidence) = evidence_type {
                    tags.push_str(&format!(";+freeq.at/evidence-type={evidence}"));
                }
                writer
                    .write_all(format!("@{tags} TAGMSG {channel}\r\n").as_bytes())
                    .await?;
                writer
                    .write_all(format!("@{tags} PRIVMSG {channel} :{human_text}\r\n").as_bytes())
                    .await?;
                return Ok(());
            };

            let mut tags = std::collections::HashMap::from([
                ("+freeq.at/event".to_string(), event_type),
                ("+freeq.at/payload".to_string(), payload),
            ]);
            if let Some(rid) = ref_id {
                tags.insert("+freeq.at/ref".to_string(), rid);
            }
            if let Some(evidence) = evidence_type {
                tags.insert("+freeq.at/evidence-type".to_string(), evidence);
            }
            let mut event_tags = tags.clone();
            event_tags.insert(crate::chatsig::EVENT_ID_TAG.to_string(), event_id.clone());
            event_tags.insert(crate::sigtag::SIG_TAG.to_string(), signature);
            let tagmsg = crate::irc::Message {
                tags: event_tags,
                prefix: None,
                command: "TAGMSG".to_string(),
                params: vec![channel.clone()],
            };
            writer.write_all(format!("{tagmsg}\r\n").as_bytes()).await?;

            // The companion is an ordinary message signing its own id. The
            // TAGMSG *is* the event — it carries the event id in a covered
            // field — and the companion is a rendering of it, so it carries
            // the event tags a reader draws a card from and nothing more.
            sign_outgoing(
                &mut tags,
                signing_key,
                signing_did,
                &channel,
                &human_text,
                server_verifies_documents,
            );
            let privmsg = crate::irc::Message {
                tags,
                prefix: None,
                command: "PRIVMSG".to_string(),
                params: vec![channel, human_text],
            };
            writer
                .write_all(format!("{privmsg}\r\n").as_bytes())
                .await?;
        }
        Command::Act {
            target,
            event_id,
            tags,
            human_text,
            done,
        } => {
            let sent = send_act_event(
                writer,
                &target,
                &event_id,
                tags,
                &human_text,
                signing_key,
                signing_did,
                server_verifies_documents,
            )
            .await;
            // A refusal is the caller's answer, not the connection's problem:
            // the session stays up and the next send is unaffected. A write
            // that failed is the connection's problem, so it still propagates
            // — and dropping `done` unsent is what tells the caller so.
            match sent {
                Ok(refusal) => {
                    let _ = done.send(refusal);
                }
                Err(e) => return Err(e),
            }
        }
        Command::Raw(line) => {
            // Strip CRLF/NUL to prevent protocol injection via raw commands
            let safe: String = line
                .chars()
                .filter(|c| *c != '\r' && *c != '\n' && *c != '\0')
                .collect();
            tracing::debug!("[SDK] Raw command: {}", safe);
            writer.write_all(format!("{safe}\r\n").as_bytes()).await?;
            tracing::debug!("[SDK] Raw command sent OK");
        }
        Command::Quit(msg) => {
            let quit_line = match msg {
                Some(m) => format!("QUIT :{m}\r\n"),
                None => "QUIT\r\n".to_string(),
            };
            writer.write_all(quit_line.as_bytes()).await?;
        }
    }
    Ok(())
}

async fn handle_cap_response<W: AsyncWrite + Unpin>(
    msg: &Message,
    signer: &Option<Arc<dyn ChallengeSigner>>,
    web_token: &Option<String>,
    writer: &mut W,
    sasl_in_progress: &mut bool,
    caps_acked: &CapsAcked,
) -> Result<()> {
    let subcmd = msg.params.get(1).map(|s| s.to_ascii_uppercase());
    match subcmd.as_deref() {
        Some("LS") => {
            let caps_str = msg.params.last().map(|s| s.as_str()).unwrap_or("");
            // Capture the peer's advertised draft/multiline policy so sends
            // respect its actual limits instead of assuming freeq's defaults.
            if let Some(policy) = parse_multiline_cap(caps_str) {
                caps_acked.lock().multiline_policy = Some(policy);
            }
            let mut req_caps = Vec::new();
            if caps_str.contains("message-tags") {
                req_caps.push("message-tags");
            }
            for cap in &[
                "server-time",
                "batch",
                "echo-message",
                "away-notify",
                "account-notify",
                "account-tag",
                "extended-join",
                "draft/chathistory",
                "draft/multiline",
                "draft/read-marker",
                // Task events are delivered only to a session that asked for
                // them, so a consumer rendering task cards has to ask.
                ACT_CAP,
                // Requested rather than merely read off the LS line: the ACK
                // is the server's own confirmation that it verifies chat
                // documents, and signing is gated on it (see `MSGSIG_CAP`).
                MSGSIG_CAP,
            ] {
                if caps_str.contains(cap) {
                    req_caps.push(cap);
                }
            }
            if caps_str.contains("sasl") && (signer.is_some() || web_token.is_some()) {
                req_caps.push("sasl");
            }
            if req_caps.is_empty() {
                // eprintln!("  No caps to request, sending CAP END");
                writer.write_all(b"CAP END\r\n").await?;
            } else {
                // eprintln!("  Requesting: {}", req_caps.join(" "));
                let req = format!("CAP REQ :{}\r\n", req_caps.join(" "));
                writer.write_all(req.as_bytes()).await?;
            }
        }
        Some("ACK") => {
            let caps = msg.params.last().map(|s| s.as_str()).unwrap_or("");
            // Record which caps the server ACKed so `ClientHandle::privmsg`
            // can route `\n`-bearing text to a draft/multiline BATCH.
            {
                let mut state = caps_acked.lock();
                for cap in caps.split_whitespace() {
                    state.acked.insert(cap.to_string());
                }
            }
            if caps.contains("sasl") {
                *sasl_in_progress = true;
                // Both web-token and ATPROTO-CHALLENGE use the same SASL mechanism;
                // the method field in the JSON payload distinguishes them.
                writer
                    .write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
                    .await?;
            } else {
                writer.write_all(b"CAP END\r\n").await?;
            }
        }
        Some("NAK") => {
            // eprintln!("  Capabilities rejected, sending CAP END");
            writer.write_all(b"CAP END\r\n").await?;
        }
        _ => {}
    }
    Ok(())
}

/// Parse a `draft/multiline=max-bytes=N,max-lines=M` token out of a CAP LS
/// value into `(max_bytes, max_lines)`. Unspecified fields fall back to the
/// built-in defaults. Returns `None` if the cap isn't advertised with params
/// (bare `draft/multiline`), leaving the caller on its defaults.
fn parse_multiline_cap(caps_str: &str) -> Option<(usize, usize)> {
    let value = caps_str
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("draft/multiline="))?;
    let mut max_bytes = MULTILINE_MAX_BYTES;
    let mut max_lines = MULTILINE_MAX_LINES;
    for kv in value.split(',') {
        let mut it = kv.splitn(2, '=');
        match (it.next(), it.next().and_then(|n| n.parse::<usize>().ok())) {
            (Some("max-bytes"), Some(n)) => max_bytes = n,
            (Some("max-lines"), Some(n)) => max_lines = n,
            _ => {}
        }
    }
    Some((max_bytes, max_lines))
}

async fn handle_authenticate_challenge<W: AsyncWrite + Unpin>(
    msg: &Message,
    signer: &dyn ChallengeSigner,
    writer: &mut W,
) -> Result<()> {
    let encoded_challenge = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    // eprintln!("  Received SASL challenge ({} bytes encoded)", encoded_challenge.len());

    // Decode the challenge to raw bytes — these are what we sign
    let challenge_bytes = auth::decode_challenge_bytes(encoded_challenge)?;
    // eprintln!("  Challenge decoded ({} bytes), signing with {}...", challenge_bytes.len(), signer.did());

    // Produce the response using the signer
    let response = signer.respond(&challenge_bytes)?;
    let encoded = auth::encode_response(&response);
    // eprintln!("  Sending AUTHENTICATE response ({} bytes)", encoded.len());

    writer
        .write_all(format!("AUTHENTICATE {encoded}\r\n").as_bytes())
        .await?;

    Ok(())
}

// ── Reconnect helper ──

/// Configuration for automatic reconnection.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Initial delay before first reconnect attempt.
    pub initial_delay: std::time::Duration,
    /// Maximum delay between reconnect attempts.
    pub max_delay: std::time::Duration,
    /// Multiplier for exponential backoff.
    pub backoff_factor: f64,
    /// Channels to rejoin after reconnecting.
    pub channels: Vec<String>,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
            backoff_factor: 2.0,
            channels: Vec::new(),
        }
    }
}

/// Run an event loop with automatic reconnection.
///
/// The `handler` is called for each event. When disconnected, the loop
/// reconnects with exponential backoff and rejoins configured channels.
///
/// Returns only on unrecoverable errors or when the handler returns `Err`.
///
/// # Example
///
/// ```rust,no_run
/// use freeq_sdk::client::{ConnectConfig, ReconnectConfig, run_with_reconnect};
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = ConnectConfig { /* ... */ ..Default::default() };
/// let reconnect = ReconnectConfig {
///     channels: vec!["#bots".into()],
///     ..Default::default()
/// };
///
/// run_with_reconnect(config, None, reconnect, |handle, event| {
///     Box::pin(async move {
///         // handle event
///         Ok(())
///     })
/// }).await
/// # }
/// ```
pub async fn run_with_reconnect<F>(
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    reconnect_config: ReconnectConfig,
    handler: F,
) -> Result<()>
where
    F: Fn(
            ClientHandle,
            Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
{
    let mut delay = reconnect_config.initial_delay;
    let mut consecutive_failures = 0u32;

    loop {
        // Connect
        let conn = match establish_connection(&config).await {
            Ok(c) => {
                consecutive_failures = 0;
                delay = reconnect_config.initial_delay;
                c
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(
                    error = %e,
                    attempt = consecutive_failures,
                    delay_secs = delay.as_secs(),
                    "Connection failed, retrying"
                );
                tokio::time::sleep(delay).await;
                // Exponential backoff with jitter
                let jitter = rand_jitter(delay.as_millis() as u64 / 4);
                delay = std::time::Duration::from_millis(
                    ((delay.as_millis() as f64 * reconnect_config.backoff_factor) as u64 + jitter)
                        .min(reconnect_config.max_delay.as_millis() as u64),
                );
                continue;
            }
        };

        let (handle, mut events) = connect_with_stream(conn, config.clone(), signer.clone());

        // Event loop
        let mut disconnected = false;
        while let Some(event) = events.recv().await {
            // Join configured channels once registered with the server.
            // (JOINs sent before registration are silently dropped by IRC servers.)
            if matches!(&event, Event::Registered { .. }) {
                for ch in &reconnect_config.channels {
                    let _ = handle.join(ch).await;
                }
            }
            if matches!(&event, Event::Disconnected { .. }) {
                disconnected = true;
            }
            if let Err(e) = handler(handle.clone(), event).await {
                tracing::error!(error = %e, "Handler error");
                // Non-fatal: continue processing
            }
            if disconnected {
                break;
            }
        }

        tracing::info!(delay_secs = delay.as_secs(), "Disconnected, will reconnect");
        tokio::time::sleep(delay).await;
        let jitter = rand_jitter(delay.as_millis() as u64 / 4);
        delay = std::time::Duration::from_millis(
            ((delay.as_millis() as f64 * reconnect_config.backoff_factor) as u64 + jitter)
                .min(reconnect_config.max_delay.as_millis() as u64),
        );
    }
}

/// Simple jitter: random value 0..max using thread_rng.
fn rand_jitter(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    rand::random::<u64>() % max
}

#[cfg(test)]
mod multiline_tests {
    use super::*;

    /// Reassemble one batch's chunks per the wire concat rules (mirrors
    /// `dispatch_assembled_multiline`): a non-concat chunk after the first
    /// joins with `\n`, a concat chunk joins with nothing.
    fn reassemble(chunks: &[MultilineChunk]) -> String {
        let mut out = String::new();
        for (i, c) in chunks.iter().enumerate() {
            if i > 0 && !c.concat {
                out.push('\n');
            }
            out.push_str(&c.body);
        }
        out
    }

    #[test]
    fn short_multiline_is_byte_identical_and_never_splits_lines() {
        let text = "alpha\nbeta\ngamma";
        let chunks = chunk_multiline_body(text, MULTILINE_PER_CHUNK_BYTES);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| !c.concat));
        assert_eq!(reassemble(&chunks), text);
    }

    #[test]
    fn blank_source_lines_survive_as_empty_chunks() {
        let text = "a\n\nb\n"; // trailing newline => empty final line
        let chunks = chunk_multiline_body(text, MULTILINE_PER_CHUNK_BYTES);
        // "a", "", "b", "" — every one a non-concat chunk.
        assert_eq!(chunks.len(), 4);
        assert!(chunks.iter().all(|c| !c.concat));
        assert_eq!(chunks[1].body, "");
        assert_eq!(chunks[3].body, "");
        assert_eq!(reassemble(&chunks), text);
    }

    #[test]
    fn long_line_hard_splits_into_concat_continuations() {
        let line = "x".repeat(20_000);
        let chunks = chunk_multiline_body(&line, MULTILINE_PER_CHUNK_BYTES);
        assert!(chunks.len() > 1);
        assert!(!chunks[0].concat, "first chunk opens the line");
        assert!(
            chunks[1..].iter().all(|c| c.concat),
            "rest are continuations"
        );
        assert!(
            chunks
                .iter()
                .all(|c| c.body.len() <= MULTILINE_PER_CHUNK_BYTES)
        );
        assert_eq!(reassemble(&chunks), line);
    }

    #[test]
    fn mixed_short_and_long_lines_round_trip() {
        let text = format!("head\n{}\ntail\n\nfoot", "y".repeat(15_000));
        let chunks = chunk_multiline_body(&text, MULTILINE_PER_CHUNK_BYTES);
        assert_eq!(reassemble(&chunks), text);
    }

    #[test]
    fn splits_only_on_utf8_char_boundaries() {
        // Budget of 3 bytes against a 2-byte-per-char string: each chunk must
        // land on a char boundary (no panic, no mojibake on reassembly).
        let text = "é".repeat(10); // 2 bytes each => 20 bytes
        let chunks = chunk_multiline_body(&text, 3);
        assert!(chunks.iter().all(|c| c.body.chars().all(|ch| ch == 'é')));
        assert_eq!(reassemble(&chunks), text);
    }

    #[test]
    fn single_char_wider_than_budget_still_makes_progress() {
        // A 3-byte char against a 1-byte budget must not loop forever; it
        // takes the whole char.
        let text = "€€"; // 3 bytes each
        let chunks = chunk_multiline_body(text, 1);
        assert_eq!(chunks.len(), 2);
        assert_eq!(reassemble(&chunks), text);
    }

    #[test]
    fn grouping_keeps_one_batch_under_policy() {
        let chunks = chunk_multiline_body("a\nb\nc", MULTILINE_PER_CHUNK_BYTES);
        let groups = group_chunks_into_batches(chunks, MULTILINE_MAX_LINES, MULTILINE_MAX_BYTES);
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn grouping_splits_when_over_max_lines() {
        // 250 single-char lines against a max of 100 lines/batch => 3 batches.
        let text = (0..250).map(|_| "z").collect::<Vec<_>>().join("\n");
        let chunks = chunk_multiline_body(&text, MULTILINE_PER_CHUNK_BYTES);
        let groups = group_chunks_into_batches(chunks, MULTILINE_MAX_LINES, MULTILINE_MAX_BYTES);
        assert_eq!(groups.len(), 3);
        assert!(groups.iter().all(|g| g.len() <= MULTILINE_MAX_LINES));
        // Every batch opens on a non-concat chunk (boundary never severs a line).
        assert!(groups.iter().all(|g| !g[0].concat));
    }

    #[test]
    fn grouping_never_severs_a_hard_split_line() {
        // One line long enough to exceed max-bytes on its own: its concat
        // continuation chunks must all stay in the SAME batch as the opener.
        let text = "w".repeat(MULTILINE_MAX_BYTES + 5_000);
        let chunks = chunk_multiline_body(&text, MULTILINE_PER_CHUNK_BYTES);
        let groups = group_chunks_into_batches(chunks, MULTILINE_MAX_LINES, MULTILINE_MAX_BYTES);
        // A concat chunk is never the first in a batch.
        assert!(groups.iter().all(|g| !g[0].concat));
    }

    #[test]
    fn parses_advertised_multiline_policy() {
        let ls = "server-time batch draft/multiline=max-bytes=12000,max-lines=42 sasl";
        assert_eq!(parse_multiline_cap(ls), Some((12000, 42)));
    }

    #[test]
    fn bare_multiline_cap_yields_no_override() {
        // No params advertised => caller stays on its defaults.
        assert_eq!(parse_multiline_cap("batch draft/multiline sasl"), None);
        assert_eq!(parse_multiline_cap("server-time batch sasl"), None);
    }

    #[test]
    fn partial_multiline_policy_falls_back_per_field() {
        // Only max-lines advertised => max-bytes keeps the built-in default.
        assert_eq!(
            parse_multiline_cap("draft/multiline=max-lines=7"),
            Some((MULTILINE_MAX_BYTES, 7))
        );
    }

    /// Assemble per concat rules — concat=true joins with no separator,
    /// concat=false joins with `\n`. The first chunk's `concat` is
    /// irrelevant (no predecessor).
    #[tokio::test]
    async fn assemble_no_concat_joins_with_newline() {
        let (tx, mut rx) = mpsc::channel(8);
        let batch = InboundMultilineBatch {
            target: "#room".to_string(),
            from: "bob".to_string(),
            opener_tags: std::collections::HashMap::new(),
            lines: vec![
                MultilineChunk {
                    body: "hello".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "world".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "foo".into(),
                    concat: false,
                },
            ],
            parent_batch_id: None,
        };
        dispatch_assembled_multiline(&tx, batch, None).await;
        match rx.recv().await.unwrap() {
            Event::Message {
                from, target, text, ..
            } => {
                assert_eq!(from, "bob");
                assert_eq!(target, "#room");
                assert_eq!(text, "hello\nworld\nfoo");
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assemble_concat_joins_without_separator() {
        let (tx, mut rx) = mpsc::channel(8);
        let batch = InboundMultilineBatch {
            target: "#room".to_string(),
            from: "bob".to_string(),
            opener_tags: std::collections::HashMap::new(),
            lines: vec![
                MultilineChunk {
                    body: "alpha".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "beta".into(),
                    concat: true,
                },
                MultilineChunk {
                    body: "gamma".into(),
                    concat: false,
                },
            ],
            parent_batch_id: None,
        };
        dispatch_assembled_multiline(&tx, batch, None).await;
        match rx.recv().await.unwrap() {
            Event::Message { text, .. } => assert_eq!(text, "alphabeta\ngamma"),
            other => panic!("expected Message, got {other:?}"),
        }
    }

    /// Opener tags carry through to the assembled Message — receivers
    /// see msgid, time, etc. on the one synthetic event, not on the
    /// individual chunks.
    #[tokio::test]
    async fn assemble_threads_opener_tags() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut opener_tags = std::collections::HashMap::new();
        opener_tags.insert("msgid".to_string(), "01XYZ".to_string());
        opener_tags.insert("time".to_string(), "2026-05-29T17:00:00.000Z".to_string());
        opener_tags.insert("+freeq.at/payload".to_string(), "{}".to_string());
        let batch = InboundMultilineBatch {
            target: "#room".to_string(),
            from: "bob".to_string(),
            opener_tags,
            lines: vec![
                MultilineChunk {
                    body: "x".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "y".into(),
                    concat: false,
                },
            ],
            parent_batch_id: None,
        };
        dispatch_assembled_multiline(&tx, batch, None).await;
        match rx.recv().await.unwrap() {
            Event::Message { tags, .. } => {
                assert_eq!(tags.get("msgid").map(String::as_str), Some("01XYZ"));
                assert_eq!(
                    tags.get("time").map(String::as_str),
                    Some("2026-05-29T17:00:00.000Z")
                );
                assert_eq!(
                    tags.get("+freeq.at/payload").map(String::as_str),
                    Some("{}")
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    /// Outbound: Command::SendMultiline writes BATCH + N PRIVMSGs + BATCH-
    /// to the wire, with the batch tag on each chunk and concat tags
    /// passed through.
    #[tokio::test]
    async fn send_multiline_emits_batch_frames() {
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::SendMultiline {
            target: "#room".into(),
            chunks: vec![
                MultilineChunk {
                    body: "one".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "two".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "three".into(),
                    concat: false,
                },
            ],
            opener_tags: std::collections::HashMap::new(),
        };
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        // Find the batch id from the opener
        let opener_line = wire.lines().next().unwrap();
        assert!(opener_line.starts_with("BATCH +"));
        assert!(opener_line.contains("draft/multiline #room"));
        let batch_id = opener_line
            .strip_prefix("BATCH +")
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        // 3 chunks, all with batch=<id>
        for line in &["one", "two", "three"] {
            let pat = format!("@batch={batch_id} PRIVMSG #room :{line}");
            assert!(
                wire.contains(&pat),
                "expected line `{pat}` in wire:\n{wire}"
            );
        }
        // Closer
        assert!(wire.contains(&format!("BATCH -{batch_id}")));
    }

    #[tokio::test]
    async fn send_multiline_concat_tag_on_chunks() {
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::SendMultiline {
            target: "#room".into(),
            chunks: vec![
                MultilineChunk {
                    body: "ENC1:abc".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "def".into(),
                    concat: true,
                },
                MultilineChunk {
                    body: "ghi".into(),
                    concat: true,
                },
            ],
            opener_tags: std::collections::HashMap::new(),
        };
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        // First chunk: no concat tag
        assert!(wire.contains(":ENC1:abc"));
        let first_chunk_line = wire.lines().find(|l| l.contains(":ENC1:abc")).unwrap();
        assert!(!first_chunk_line.contains("draft/multiline-concat"));
        // Second + third chunks: concat tag present
        let def_line = wire.lines().find(|l| l.ends_with(":def")).unwrap();
        let ghi_line = wire.lines().find(|l| l.ends_with(":ghi")).unwrap();
        assert!(def_line.contains("draft/multiline-concat"));
        assert!(ghi_line.contains("draft/multiline-concat"));
    }

    #[tokio::test]
    async fn send_multiline_opener_tags_on_opener_only() {
        let mut buf: Vec<u8> = Vec::new();
        let mut opener_tags = std::collections::HashMap::new();
        opener_tags.insert("+reply".to_string(), "01ORIG".to_string());
        let cmd = Command::SendMultiline {
            target: "#room".into(),
            chunks: vec![
                MultilineChunk {
                    body: "a".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "b".into(),
                    concat: false,
                },
            ],
            opener_tags,
        };
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let opener = wire.lines().find(|l| l.contains("BATCH +")).unwrap();
        let chunk_a = wire.lines().find(|l| l.ends_with(":a")).unwrap();
        let chunk_b = wire.lines().find(|l| l.ends_with(":b")).unwrap();
        assert!(opener.contains("+reply=01ORIG"));
        assert!(!chunk_a.contains("+reply=01ORIG"));
        assert!(!chunk_b.contains("+reply=01ORIG"));
    }

    /// When a signing key is present, the BATCH opener carries a
    /// `+freeq.at/sig` tag computed over the ASSEMBLED body (not any
    /// single chunk). The server's verification reads the sig from
    /// the assembled-message tags after multiline dispatch, so this
    /// is the only placement that lets client sigs verify.
    #[tokio::test]
    async fn send_multiline_signs_assembled_body_on_opener() {
        use ed25519_dalek::SigningKey;
        // ed25519-dalek 2.x re-exports the rand_core trait it needs.
        use ed25519_dalek::ed25519::signature::rand_core::OsRng;
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let did = "did:plc:testkey".to_string();
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::SendMultiline {
            target: "#room".into(),
            chunks: vec![
                MultilineChunk {
                    body: "hello".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "world".into(),
                    concat: false,
                },
                MultilineChunk {
                    body: "foo".into(),
                    concat: false,
                },
            ],
            opener_tags: std::collections::HashMap::new(),
        };
        execute_command(&mut buf, cmd, &Some(key.clone()), &Some(did.clone()), true)
            .await
            .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let opener = wire.lines().find(|l| l.contains("BATCH +")).unwrap();
        // Sig present on opener
        assert!(opener.contains("+freeq.at/sig="), "opener: {opener}");
        // NOT on any chunk
        for line in &["hello", "world", "foo"] {
            let chunk_line = wire
                .lines()
                .find(|l| l.ends_with(&format!(":{line}")))
                .unwrap();
            assert!(
                !chunk_line.contains("+freeq.at/sig"),
                "chunk should not carry sig: {chunk_line}"
            );
        }
        // The sig MUST verify over the assembled body — and now it does so
        // deterministically. The old canonical folded a wall clock the signer
        // minted and never transmitted, so this test used to try every second
        // in the last five and accept any hit. A receiver had no such luxury.
        let opener_tags = crate::irc::Message::parse(opener)
            .expect("opener parses")
            .tags;
        let sig_tag = opener_tags
            .get("+freeq.at/sig")
            .expect("opener carries the signature");
        let event_id = opener_tags
            .get(crate::chatsig::EVENT_ID_TAG)
            .expect("a signature covers an id the signer minted");
        let venue = crate::chatsig::channel_venue("#room");
        let doc = crate::chatsig::ChatDoc::message(&did, event_id, &venue, "hello\nworld\nfoo");
        doc.verify(sig_tag, &key.verifying_key())
            .expect("sig verifies over the assembled body, first try");
    }

    #[tokio::test]
    async fn send_multiline_empty_opener_tags_omits_tag_block() {
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::SendMultiline {
            target: "#room".into(),
            chunks: vec![MultilineChunk {
                body: "x".into(),
                concat: false,
            }],
            opener_tags: std::collections::HashMap::new(),
        };
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let opener = wire.lines().next().unwrap();
        // No leading "@..." tag block when there are no opener tags
        assert!(opener.starts_with("BATCH +"));
    }

    /// Auto-routing: `privmsg` with `\n`-bearing text and the
    /// `draft/multiline` + `batch` caps acked sends `SendMultiline`,
    /// one chunk per source line.
    #[tokio::test]
    async fn privmsg_auto_routes_to_multiline_when_cap_acked() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        caps_acked
            .lock()
            .acked
            .insert("draft/multiline".to_string());
        caps_acked.lock().acked.insert("batch".to_string());
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked,
            did_maps,
        };
        handle.privmsg("#test", "alpha\nbeta\ngamma").await.unwrap();
        match cmd_rx.recv().await.unwrap() {
            Command::SendMultiline {
                target,
                chunks,
                opener_tags,
            } => {
                assert_eq!(target, "#test");
                assert!(opener_tags.is_empty());
                assert_eq!(chunks.len(), 3);
                assert_eq!(chunks[0].body, "alpha");
                assert_eq!(chunks[1].body, "beta");
                assert_eq!(chunks[2].body, "gamma");
                for c in &chunks {
                    assert!(!c.concat, "auto-routed chunks default to concat=false");
                }
            }
            other => panic!("expected SendMultiline, got {other:?}"),
        }
    }

    /// Without the multiline cap, `privmsg` falls back to a single
    /// `Privmsg` (existing behavior preserved — non-breaking).
    #[tokio::test]
    async fn privmsg_falls_back_to_single_when_cap_not_acked() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        // No caps acked
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked,
            did_maps,
        };
        handle.privmsg("#test", "a\nb").await.unwrap();
        match cmd_rx.recv().await.unwrap() {
            Command::Privmsg { target, text, .. } => {
                assert_eq!(target, "#test");
                assert_eq!(text, "a\nb");
            }
            other => panic!("expected Privmsg, got {other:?}"),
        }
    }

    /// send_tagged with `\n`-bearing text auto-routes to SendMultiline
    /// with the caller's tags moved onto the BATCH opener — preserving
    /// the tag semantics (e.g. commit-reveal payloads) under the
    /// multiline path.
    #[tokio::test]
    async fn send_tagged_auto_routes_to_multiline_with_opener_tags() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        caps_acked
            .lock()
            .acked
            .insert("draft/multiline".to_string());
        caps_acked.lock().acked.insert("batch".to_string());
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked,
            did_maps,
        };
        let mut tags = std::collections::HashMap::new();
        tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
        tags.insert("+freeq.at/payload".to_string(), "%7B%7D".to_string());
        handle.send_tagged("#test", "x\ny\nz", tags).await.unwrap();
        match cmd_rx.recv().await.unwrap() {
            Command::SendMultiline {
                target,
                chunks,
                opener_tags,
            } => {
                assert_eq!(target, "#test");
                assert_eq!(chunks.len(), 3);
                assert_eq!(
                    opener_tags.get("+freeq.at/event").map(String::as_str),
                    Some("reveal")
                );
                assert_eq!(
                    opener_tags.get("+freeq.at/payload").map(String::as_str),
                    Some("%7B%7D")
                );
            }
            other => panic!("expected SendMultiline, got {other:?}"),
        }
    }

    /// Single-line text always uses `Privmsg`, never `SendMultiline`,
    /// regardless of cap state.
    #[tokio::test]
    async fn privmsg_single_line_never_routes_to_multiline() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        caps_acked
            .lock()
            .acked
            .insert("draft/multiline".to_string());
        caps_acked.lock().acked.insert("batch".to_string());
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked,
            did_maps,
        };
        handle.privmsg("#test", "hello world").await.unwrap();
        match cmd_rx.recv().await.unwrap() {
            Command::Privmsg { target, text, .. } => {
                assert_eq!(target, "#test");
                assert_eq!(text, "hello world");
            }
            other => panic!("expected Privmsg, got {other:?}"),
        }
    }

    /// Whether a DM peer is addressing-grade known is something a client has
    /// to be able to ask: it is the difference between a signed first DM and
    /// an unsigned one, and the fix (ask the server who they are) is only
    /// worth doing when the answer is missing.
    #[tokio::test]
    async fn a_client_can_ask_whether_a_dm_peer_is_identified() {
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        did_maps.lock().learn("bob", "did:plc:bob");
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps,
        };

        assert_eq!(
            handle.identified_dm_peer("Bob").as_deref(),
            Some("did:plc:bob"),
            "a learned binding resolves, case-insensitively"
        );
        assert_eq!(
            handle.identified_dm_peer("did:plc:carol").as_deref(),
            Some("did:plc:carol"),
            "a peer addressed by DID is already identified"
        );
        assert_eq!(
            handle.identified_dm_peer("stranger"),
            None,
            "an unknown nick is exactly the case worth asking about"
        );
        assert_eq!(
            handle.identified_dm_peer("#room"),
            None,
            "a channel is not a DM peer"
        );
    }

    /// A mutation in a DM addresses the peer's DID whenever we know it, the
    /// same resolution a message send does. Routing them differently is what
    /// left reactions and deletes in a DM unsigned: the signer derives the
    /// venue from the target it is handed, and a bare nick has no venue any
    /// verifier could rebuild.
    #[tokio::test]
    async fn a_dm_mutation_addresses_the_peer_did_when_it_is_known() {
        use ed25519_dalek::SigningKey;

        let root = "01ROOTMSGID0000000000000FF";
        let peer = "did:plc:peer";
        let did = "did:plc:mutator";
        let key = SigningKey::from_bytes(&[11u8; 32]);

        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        did_maps.lock().learn("bob", peer);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps,
        };

        handle.delete_message("bob", root).await.unwrap();
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(key.clone()),
            &Some(did.to_string()),
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert_eq!(
            sent.params,
            vec![peer.to_string()],
            "a known peer is addressed by DID: {wire}"
        );
        let sig = sent
            .tags
            .get(crate::sigtag::SIG_TAG)
            .unwrap_or_else(|| panic!("a DM mutation with a knowable venue is signed: {wire}"));
        let event_id = sent.tags.get(crate::chatsig::EVENT_ID_TAG).unwrap();
        crate::chatsig::ChatDoc::mutation(
            crate::chatsig::Mutation::Delete,
            did,
            event_id,
            &crate::chatsig::dm_venue(did, peer),
            root,
        )
        .verify(sig, &key.verifying_key())
        .expect("the mutation binds the sorted DID pair");
    }

    /// An unknown peer still gets the mutation — unsigned, addressed by nick,
    /// and without an error. A guest has no DID to resolve to, and refusing
    /// to delete your own message because the other end is a guest would be
    /// a worse failure than sending it unsigned.
    #[tokio::test]
    async fn a_dm_mutation_to_an_unknown_peer_still_sends_unsigned() {
        use ed25519_dalek::SigningKey;

        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
        };

        handle
            .react("stranger", "👍", "01ROOTMSGID000000000000GG")
            .await
            .unwrap();
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(SigningKey::from_bytes(&[12u8; 32])),
            &Some("did:plc:mutator".to_string()),
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert_eq!(sent.params, vec!["stranger".to_string()], "{wire}");
        assert!(!sent.tags.contains_key(crate::sigtag::SIG_TAG), "{wire}");
        assert_eq!(
            sent.tags.get("+react").map(String::as_str),
            Some("👍"),
            "the reaction itself still goes out: {wire}"
        );
    }

    /// Channel targets are not DM peers and must pass through resolution
    /// untouched, including the rarer `&` prefix.
    #[tokio::test]
    async fn a_channel_mutation_target_is_never_rewritten() {
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        did_maps.lock().learn("bob", "did:plc:peer");
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps,
        };

        for target in ["#room", "&local"] {
            handle.typing_start(target).await.unwrap();
            match cmd_rx.recv().await.unwrap() {
                Command::Tagmsg { target: t, .. } => assert_eq!(t, target),
                other => panic!("expected Tagmsg, got {other:?}"),
            }
        }
    }

    /// Removing a reaction travels the same signed path as adding one: the
    /// handle emits the tag shape the mutation signer already recognizes, so
    /// against a server that negotiated the cap the TAGMSG carries the event
    /// id and the signature over the removal — and against one that didn't,
    /// exactly the tags a legacy client would send.
    #[tokio::test]
    async fn unreact_is_signed_when_the_server_verifies_documents() {
        use ed25519_dalek::SigningKey;

        let root = "01ROOTMSGID0000000000000EE";
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let did = "did:plc:unreactor";

        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
        };

        // Signed against a verifying server, and the signature is over the
        // Unreact document a receiver rebuilds from this very line.
        handle.unreact("#room", "👍", root).await.unwrap();
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(key.clone()),
            &Some(did.to_string()),
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert_eq!(sent.command, "TAGMSG");
        assert_eq!(sent.params, vec!["#room".to_string()]);
        assert_eq!(
            sent.tags.get("+freeq.at/unreact").map(String::as_str),
            Some("👍"),
            "the removal names its emoji: {wire}"
        );
        assert_eq!(
            sent.tags.get("+reply").map(String::as_str),
            Some(root),
            "and the message it acts on: {wire}"
        );
        let event_id = sent
            .tags
            .get(crate::chatsig::EVENT_ID_TAG)
            .unwrap_or_else(|| panic!("event id must travel with the signature: {wire}"));
        let sig = sent
            .tags
            .get(crate::sigtag::SIG_TAG)
            .unwrap_or_else(|| panic!("a removal is durable state — sign it: {wire}"));
        crate::chatsig::ChatDoc::mutation(
            crate::chatsig::Mutation::Unreact,
            did,
            event_id,
            &crate::chatsig::channel_venue("#room"),
            root,
        )
        .with_emoji("👍")
        .verify(sig, &key.verifying_key())
        .expect("the unreact signature verifies over the mutation document");

        // And byte-identical to legacy against a server that never offered
        // the cap: no id, no signature.
        handle.unreact("#room", "👍", root).await.unwrap();
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(key),
            &Some(did.to_string()),
            false,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert!(!sent.tags.contains_key(crate::sigtag::SIG_TAG), "{wire}");
        assert!(
            !sent.tags.contains_key(crate::chatsig::EVENT_ID_TAG),
            "{wire}"
        );
    }

    /// A coordination event is the artifact the server stores and serves back
    /// as a task card and an audit row, so it signs standalone — over its own
    /// document, under the id the caller was handed.
    #[tokio::test]
    async fn a_coordination_event_is_signed_over_its_own_document() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[11u8; 32]);
        let did = "did:plc:emitter";
        let caps: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        caps.lock().acked.insert(MSGSIG_CAP.to_string());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: caps,
            did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
        };

        let task_id = handle.create_task("#room", "ship it").await.unwrap();
        assert_eq!(task_id.len(), 26, "a signed event is filed under a ULID");

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(key.clone()),
            &Some(did.to_string()),
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let mut lines = wire.lines();
        let tagmsg = crate::irc::Message::parse(lines.next().unwrap()).expect("parses");
        let privmsg = crate::irc::Message::parse(lines.next().unwrap()).expect("parses");

        assert_eq!(tagmsg.command, "TAGMSG");
        assert!(
            !tagmsg.tags.contains_key("msgid"),
            "the self-minted legacy id is gone: {wire}"
        );
        assert_eq!(
            tagmsg.tags.get(crate::chatsig::EVENT_ID_TAG),
            Some(&task_id),
            "the id the caller holds is the id the signature covers: {wire}"
        );
        let payload = tagmsg.tags.get("+freeq.at/payload").expect("payload rides");
        crate::chatsig::ChatDoc::coordination(
            did,
            &task_id,
            &crate::chatsig::channel_venue("#room"),
            "task_request",
        )
        .with_payload(payload)
        .verify(
            tagmsg.tags.get(crate::sigtag::SIG_TAG).expect("signed"),
            &key.verifying_key(),
        )
        .expect("the signature verifies over the coordination document");

        // The companion message is a message: its own id, its own signature.
        // The TAGMSG is the event; the companion is a rendering of it and
        // carries no claim to the event's id.
        assert_eq!(privmsg.command, "PRIVMSG");
        let message_id = privmsg
            .tags
            .get(crate::chatsig::EVENT_ID_TAG)
            .expect("the companion signs too");
        assert_ne!(message_id, &task_id, "each document signs its own id");
        let venue = crate::chatsig::channel_venue("#room");
        let mut doc = crate::chatsig::ChatDoc::message(did, message_id, &venue, &privmsg.params[1]);
        let coord: Vec<(String, String)> = privmsg
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        doc = doc.with_coord(coord.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        doc.verify(
            privmsg.tags.get(crate::sigtag::SIG_TAG).expect("signed"),
            &key.verifying_key(),
        )
        .expect("the companion verifies over the message document");
    }

    /// An event that refers to a task covers the reference it names:
    /// re-pointing a completion at other work would otherwise still read as
    /// signed.
    #[tokio::test]
    async fn a_coordination_event_covers_the_task_it_refers_to() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[12u8; 32]);
        let did = "did:plc:emitter";
        let root = "01KYVT1W2P0000000000000000";
        let caps: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        caps.lock().acked.insert(MSGSIG_CAP.to_string());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: caps,
            did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
        };

        handle
            .complete_task("#room", root, "done", None)
            .await
            .unwrap();
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(key.clone()),
            &Some(did.to_string()),
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let tagmsg = crate::irc::Message::parse(wire.lines().next().unwrap()).expect("parses");
        let event_id = tagmsg.tags.get(crate::chatsig::EVENT_ID_TAG).unwrap();
        let payload = tagmsg.tags.get("+freeq.at/payload").unwrap();
        let sig = tagmsg.tags.get(crate::sigtag::SIG_TAG).unwrap();
        assert_eq!(tagmsg.tags.get("+freeq.at/ref"), Some(&root.to_string()));

        let venue = crate::chatsig::channel_venue("#room");
        crate::chatsig::ChatDoc::coordination(did, event_id, &venue, "task_complete")
            .with_payload(payload)
            .with_ref(root)
            .verify(sig, &key.verifying_key())
            .expect("verifies over the document it named");
        assert!(
            crate::chatsig::ChatDoc::coordination(did, event_id, &venue, "task_complete")
                .with_payload(payload)
                .with_ref("01KYVT9ZZZ0000000000000000")
                .verify(sig, &key.verifying_key())
                .is_err(),
            "a re-pointed reference is tampering"
        );
    }

    /// Against a server that never offered the cap, the pair is the pair a
    /// pre-signing client sent — same tags, same order, same legacy id — so
    /// ref-linkage keeps working where nothing has been deployed yet.
    #[tokio::test]
    async fn a_coordination_event_against_a_legacy_server_is_the_line_it_always_was() {
        use ed25519_dalek::SigningKey;

        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let handle = ClientHandle {
            cmd_tx,
            echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
            did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
        };

        let task_id = handle
            .emit_event(
                "#room",
                "task_update",
                r#"{"phase":"reviewing","summary":"looking at it"}"#,
                Some("task-abc"),
                "🔄 [reviewing] looking at it",
            )
            .await
            .unwrap();
        assert_eq!(task_id.len(), 32, "the legacy id format is 32 hex digits");

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(SigningKey::from_bytes(&[13u8; 32])),
            &Some("did:plc:emitter".to_string()),
            false,
        )
        .await
        .unwrap();
        let tags = format!(
            "+freeq.at/event=task_update;msgid={task_id};\
             +freeq.at/payload={{\"phase\":\"reviewing\",\"summary\":\"looking%20at%20it\"}};\
             +freeq.at/ref=task-abc"
        );
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!(
                "@{tags} TAGMSG #room\r\n@{tags} PRIVMSG #room :🔄 [reviewing] looking at it\r\n"
            )
        );
    }

    /// A session key is registered only with a server that asked for the
    /// signing cap. A server that never advertised it cannot verify a client
    /// document, so it would file a public key it will never use — and the
    /// registration is a command an older server has no reason to know at all.
    /// Against such a server an updated client stays silent on the subject.
    #[tokio::test]
    async fn the_session_key_is_registered_only_where_it_can_be_used() {
        /// Drive a whole registration against a server advertising `caps`,
        /// and return everything the client wrote.
        async fn client_wire(caps: &str) -> String {
            use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let (event_tx, _event_rx) = mpsc::channel::<Event>(64);
            let (_cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
            let config = ConnectConfig {
                server_addr: "test".to_string(),
                nick: "tester".to_string(),
                user: "tester".to_string(),
                realname: "tester".to_string(),
                tls: false,
                tls_insecure: false,
                web_token: None,
                websocket_url: None,
            };
            let (reader, writer) = tokio::io::split(client_side);
            tokio::spawn(async move {
                let _ = run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    None,
                    event_tx,
                    cmd_rx,
                    Arc::new(parking_lot::Mutex::new(HashMap::new())),
                    Arc::new(parking_lot::Mutex::new(CapsState::default())),
                    Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
                )
                .await;
            });

            for line in [
                format!(":srv CAP * LS :{caps}"),
                format!(":srv CAP * ACK :{caps}"),
                ":srv 900 tester :You are now logged in as did:plc:tester".to_string(),
                ":srv 903 tester :SASL authentication successful".to_string(),
                ":srv 001 tester :Welcome".to_string(),
            ] {
                server_side
                    .write_all(format!("{line}\r\n").as_bytes())
                    .await
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }

            let mut wire = Vec::new();
            let mut chunk = vec![0u8; 4096];
            while let Ok(Ok(n)) = tokio::time::timeout(
                std::time::Duration::from_millis(120),
                server_side.read(&mut chunk),
            )
            .await
            {
                if n == 0 {
                    break;
                }
                wire.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8_lossy(&wire).into_owned()
        }

        let signing = client_wire(&format!("sasl message-tags server-time {MSGSIG_CAP}")).await;
        assert!(
            signing.contains("MSGSIG "),
            "a server that verifies documents gets the key: {signing:?}"
        );

        let legacy = client_wire("sasl message-tags server-time").await;
        assert!(
            !legacy.contains("MSGSIG"),
            "a server that never offered the cap must not be sent a key: {legacy:?}"
        );
        assert!(
            legacy.contains("CAP REQ"),
            "the rest of registration is unchanged: {legacy:?}"
        );
    }

    /// A task event is only delivered to a session that asked for it: the
    /// server gates act TAGMSGs on the `freeq.at/act` cap being acked. A
    /// client that renders task cards but never asks receives nothing at all.
    #[tokio::test]
    async fn a_client_asks_for_the_task_events_it_renders() {
        async fn requested_caps(advertised: &str) -> String {
            use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

            let (client_side, mut server_side) = tokio::io::duplex(8192);
            let (event_tx, _event_rx) = mpsc::channel::<Event>(64);
            let (_cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
            let config = ConnectConfig {
                server_addr: "test".to_string(),
                nick: "tester".to_string(),
                user: "tester".to_string(),
                realname: "tester".to_string(),
                tls: false,
                tls_insecure: false,
                web_token: None,
                websocket_url: None,
            };
            let (reader, writer) = tokio::io::split(client_side);
            tokio::spawn(async move {
                let _ = run_irc(
                    BufReader::new(reader),
                    writer,
                    &config,
                    None,
                    event_tx,
                    cmd_rx,
                    Arc::new(parking_lot::Mutex::new(HashMap::new())),
                    Arc::new(parking_lot::Mutex::new(CapsState::default())),
                    Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
                )
                .await;
            });

            server_side
                .write_all(format!(":srv CAP * LS :{advertised}\r\n").as_bytes())
                .await
                .unwrap();
            let mut wire = Vec::new();
            let mut chunk = vec![0u8; 4096];
            while let Ok(Ok(n)) = tokio::time::timeout(
                std::time::Duration::from_millis(150),
                server_side.read(&mut chunk),
            )
            .await
            {
                if n == 0 {
                    break;
                }
                wire.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8_lossy(&wire).into_owned()
        }

        let offered = requested_caps("message-tags server-time batch freeq.at/act").await;
        assert!(
            offered.contains("freeq.at/act"),
            "a server offering task events is asked for them: {offered:?}"
        );

        let absent = requested_caps("message-tags server-time batch").await;
        assert!(
            !absent.contains("freeq.at/act"),
            "a server that never offered it is not asked: {absent:?}"
        );
    }

    /// CHATHISTORY replays multi-line messages as a `draft/multiline`
    /// BATCH nested inside the outer `chathistory` BATCH. This test
    /// drives that exact wire shape through `run_irc` and verifies the
    /// SDK assembles the inner batch into one `Event::Message` with
    /// the full body — the bug we suspected on Android shows up here
    /// if it's actually in the SDK rather than the Android UI.
    #[tokio::test]
    async fn nested_chathistory_batch_assembles_inner_multiline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

        let (client_side, mut server_side) = tokio::io::duplex(8192);
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(32);
        let (_cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
        let echo_registry: EchoRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        let config = ConnectConfig {
            server_addr: "test".to_string(),
            nick: "tester".to_string(),
            user: "tester".to_string(),
            realname: "tester".to_string(),
            tls: false,
            tls_insecure: false,
            web_token: None,
            websocket_url: None,
        };
        let (reader, writer) = tokio::io::split(client_side);

        tokio::spawn(async move {
            let _ = run_irc(
                BufReader::new(reader),
                writer,
                &config,
                None,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await;
        });

        // Drain whatever run_irc writes on startup (CAP LS / NICK / USER)
        // so the duplex buffer doesn't fill and block.
        let mut drain = vec![0u8; 1024];
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_millis(150),
            server_side.read(&mut drain),
        )
        .await;

        // Server-side wire: chathistory BATCH containing an inner
        // draft/multiline BATCH (two chunks) plus a regular PRIVMSG
        // sibling, then the chathistory closer. Matches what
        // freeq-server emits for stored multi-line rows during
        // CHATHISTORY replay (see freeq-server src/connection/messaging.rs
        // around the "nested BATCH path" comment).
        let wire = concat!(
            ":srv BATCH +cht1 chathistory #room\r\n",
            "@msgid=ML1;time=2026-05-30T18:00:00.000Z;batch=cht1 ",
            ":alice!a@h BATCH +ml1 draft/multiline #room\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :first line\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :second line\r\n",
            "@batch=cht1 BATCH -ml1\r\n",
            "@batch=cht1;msgid=R2 :bob!b@h PRIVMSG #room :sibling regular msg\r\n",
            ":srv BATCH -cht1\r\n",
        );
        server_side.write_all(wire.as_bytes()).await.unwrap();
        server_side.flush().await.unwrap();

        // Collect events until we hit the BatchEnd for cht1, or timeout.
        let mut events = Vec::new();
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(800), async {
            while let Some(ev) = event_rx.recv().await {
                let done = matches!(&ev, Event::BatchEnd { id } if id == "cht1");
                events.push(ev);
                if done {
                    break;
                }
            }
        })
        .await;

        // The assembled multi-line should arrive as Event::Message with
        // text = "first line\nsecond line". Filter out RawLine noise.
        let assembled: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();

        assert!(
            assembled.iter().any(|t| *t == "first line\nsecond line"),
            "assembled multi-line message not found. messages dispatched: {assembled:#?}\nall events: {events:#?}",
        );
        assert!(
            assembled.iter().any(|t| t.contains("sibling regular msg")),
            "regular sibling PRIVMSG should also have been dispatched. got: {assembled:#?}",
        );
        let assembled_multiline_tags = events.iter().find_map(|e| match e {
            Event::Message { text, tags, .. } if text == "first line\nsecond line" => Some(tags),
            _ => None,
        });
        assert_eq!(
            assembled_multiline_tags
                .and_then(|tags| tags.get("batch"))
                .map(String::as_str),
            Some("cht1"),
            "assembled nested multiline history message must retain parent chathistory batch tag. events: {events:#?}",
        );
    }

    /// Same as the prior test but with the exact wire shape that smoke
    /// scenario B10 produces during CHATHISTORY replay: a multi-line
    /// message whose body is a label + a fenced code block (backticks +
    /// rust source). If the SDK assembles this with the full text
    /// preserved byte-exact, any "only line 1 shows" symptom on a
    /// client is the client's render layer, not the SDK.
    #[tokio::test]
    async fn nested_chathistory_batch_assembles_codeblock_byte_exact() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

        let (client_side, mut server_side) = tokio::io::duplex(8192);
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(32);
        let (_cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
        let echo_registry: EchoRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        let config = ConnectConfig {
            server_addr: "test".to_string(),
            nick: "tester".to_string(),
            user: "tester".to_string(),
            realname: "tester".to_string(),
            tls: false,
            tls_insecure: false,
            web_token: None,
            websocket_url: None,
        };
        let (reader, writer) = tokio::io::split(client_side);

        tokio::spawn(async move {
            let _ = run_irc(
                BufReader::new(reader),
                writer,
                &config,
                None,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await;
        });

        let mut drain = vec![0u8; 1024];
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_millis(150),
            server_side.read(&mut drain),
        )
        .await;

        // Exact b10 body: label + fenced rust block, as the smoke sends.
        // Six lines = six chunks in CHATHISTORY replay.
        let wire = concat!(
            ":srv BATCH +cht1 chathistory #room\r\n",
            "@msgid=B10;time=2026-05-30T18:00:00.000Z;batch=cht1 ",
            ":alice!a@h BATCH +ml1 draft/multiline #room\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :b10-stamp\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :```\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :fn main() {\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :    println!(\"hello\");\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :}\r\n",
            "@batch=ml1 :alice!a@h PRIVMSG #room :```\r\n",
            "@batch=cht1 BATCH -ml1\r\n",
            ":srv BATCH -cht1\r\n",
        );
        server_side.write_all(wire.as_bytes()).await.unwrap();
        server_side.flush().await.unwrap();

        let mut events = Vec::new();
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(800), async {
            while let Some(ev) = event_rx.recv().await {
                let done = matches!(&ev, Event::BatchEnd { id } if id == "cht1");
                events.push(ev);
                if done {
                    break;
                }
            }
        })
        .await;

        let expected = "b10-stamp\n```\nfn main() {\n    println!(\"hello\");\n}\n```";
        let got = events.iter().find_map(|e| match e {
            Event::Message { text, .. } if text.starts_with("b10-stamp") => Some(text.clone()),
            _ => None,
        });
        assert_eq!(
            got.as_deref(),
            Some(expected),
            "codeblock body should be assembled byte-exact. events: {events:#?}",
        );
    }
}

#[cfg(test)]
mod connect_config_tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(ConnectConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_empty_and_oversized_nick() {
        let mut c = ConnectConfig::default();
        c.nick = String::new();
        assert!(c.validate().is_err());
        c.nick = "x".repeat(65);
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_nick_with_protocol_characters() {
        for bad in ["a b", "a,b", "a*b", "a?b", "a!b", "a@b", "a#b", "a\rb"] {
            let mut c = ConnectConfig::default();
            c.nick = bad.to_string();
            assert!(c.validate().is_err(), "nick {bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_empty_server_addr_and_user() {
        let mut c = ConnectConfig::default();
        c.server_addr = String::new();
        assert!(c.validate().is_err());

        let mut c = ConnectConfig::default();
        c.user = String::new();
        assert!(c.validate().is_err());
    }

    #[tokio::test]
    async fn establish_connection_enforces_validation() {
        let mut c = ConnectConfig::default();
        c.nick = "bad nick".to_string();
        let err = match establish_connection(&c).await {
            Ok(_) => panic!("invalid config must not connect"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("invalid ConnectConfig"),
            "got: {err}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the run_irc protocol loop and execute_command wire formatting.
//
// These complement multiline_tests (which pin batch assembly) by covering the
// core IRC state-machine paths that previously had zero dedicated tests:
//   • PING keepalive → PONG reply
//   • 001 RPL_WELCOME → Event::Registered + pending-command flush
//   • 433 ERR_NICKNAMEINUSE → suffix retry / eventual Disconnected
//   • 904 SASL failure → Event::AuthFailed + CAP END sent
//   • Command::Raw injection stripping (\r \n \0 removed)
//   • Command::Privmsg wire format without / with signing key
//   • JOIN / PART → Event::Joined / Event::Parted
//   • Server EOF → Event::Disconnected
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod irc_loop_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    /// Build a minimal ConnectConfig suitable for unit tests.
    fn test_config(nick: &str) -> ConnectConfig {
        ConnectConfig {
            server_addr: "test:6667".to_string(),
            nick: nick.to_string(),
            user: "tester".to_string(),
            realname: "Test User".to_string(),
            tls: false,
            tls_insecure: false,
            web_token: None,
            websocket_url: None,
        }
    }

    /// Spin up run_irc over a tokio duplex and drain the startup bytes
    /// (CAP LS / NICK / USER) that run_irc writes immediately.
    async fn start_run_irc(
        nick: &str,
    ) -> (
        tokio::io::DuplexStream, // "server side" – we write IRC lines here
        mpsc::Receiver<Event>,
        mpsc::Sender<Command>,
    ) {
        let (client_side, server_side) = tokio::io::duplex(16_384);
        let (event_tx, event_rx) = mpsc::channel::<Event>(64);
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
        let echo_registry: EchoRegistry = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
        let did_maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        let config = test_config(nick);

        let (reader, writer) = tokio::io::split(client_side);
        tokio::spawn(async move {
            let _ = run_irc(
                BufReader::new(reader),
                writer,
                &config,
                None,
                event_tx,
                cmd_rx,
                echo_registry,
                caps_acked,
                did_maps,
            )
            .await;
        });

        // Drain the startup burst (CAP LS / NICK / USER) so the duplex
        // buffer doesn't fill and block the spawned run_irc task.
        let mut server_side = server_side;
        let mut drain = vec![0u8; 512];
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_millis(150),
            server_side.read(&mut drain),
        )
        .await;

        (server_side, event_rx, cmd_tx)
    }

    // ── PING → PONG ──────────────────────────────────────────────────────────

    /// When the server sends a PING, run_irc must reply with PONG :<token>.
    #[tokio::test]
    async fn ping_elicits_pong_reply() {
        let (mut server, _events, _cmd) = start_run_irc("pinger").await;

        server
            .write_all(b":srv PING :abc123\r\n")
            .await
            .expect("write PING");
        server.flush().await.unwrap();

        // Read back whatever run_irc writes. PONG should appear quickly.
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            tokio::time::Duration::from_millis(400),
            server.read(&mut buf),
        )
        .await
        .expect("timeout waiting for PONG")
        .expect("read error");

        let wire = String::from_utf8_lossy(&buf[..n]);
        assert!(
            wire.contains("PONG :abc123"),
            "expected PONG :abc123 in:\n{wire}"
        );
    }

    /// PONG must also be sent when the PING token is empty.
    #[tokio::test]
    async fn ping_with_empty_token_sends_pong() {
        let (mut server, _events, _cmd) = start_run_irc("pinger2").await;

        server.write_all(b"PING :\r\n").await.unwrap();
        server.flush().await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            tokio::time::Duration::from_millis(400),
            server.read(&mut buf),
        )
        .await
        .expect("timeout waiting for PONG")
        .expect("read error");

        let wire = String::from_utf8_lossy(&buf[..n]);
        assert!(wire.contains("PONG :"), "expected PONG : in:\n{wire}");
    }

    // ── 001 RPL_WELCOME → Registered ─────────────────────────────────────────

    /// 001 must emit Event::Registered with the nick the server assigned.
    #[tokio::test]
    async fn welcome_001_emits_registered_event() {
        let (mut server, mut events, _cmd) = start_run_irc("alice").await;

        server
            .write_all(b":srv 001 alice :Welcome to IRC\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Registered { nick } = ev {
                    return nick;
                }
            }
            String::new()
        })
        .await
        .expect("timeout waiting for Registered");

        assert_eq!(got, "alice");
    }

    /// Commands sent via the cmd channel BEFORE 001 are queued and flushed
    /// to the wire once registration completes (IRC servers drop JOIN etc.
    /// sent before 001).
    #[tokio::test]
    async fn commands_queued_before_001_are_flushed_after_registration() {
        let (mut server, mut events, cmd_tx) = start_run_irc("bob").await;

        // Queue a JOIN before the server sends 001.
        cmd_tx
            .send(Command::Join("#lobby".to_string()))
            .await
            .unwrap();

        // Give run_irc time to enqueue it (it can't write yet — not registered).
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        // Now send 001 to trigger registration.
        server
            .write_all(b":srv 001 bob :Welcome\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Wait for the Registered event so we know run_irc processed 001.
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if matches!(ev, Event::Registered { .. }) {
                    break;
                }
            }
        })
        .await;

        // Now read everything run_irc wrote back to us.
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(
            tokio::time::Duration::from_millis(400),
            server.read(&mut buf),
        )
        .await
        .expect("timeout waiting for JOIN")
        .unwrap_or(0);

        let wire = String::from_utf8_lossy(&buf[..n]);
        assert!(
            wire.contains("JOIN #lobby"),
            "queued JOIN should appear after 001, got:\n{wire}"
        );
    }

    // ── 433 ERR_NICKNAMEINUSE ─────────────────────────────────────────────────

    /// On the first 433, run_irc should try nick+"1".
    #[tokio::test]
    async fn nick_in_use_first_retry_appends_1() {
        let (mut server, _events, _cmd) = start_run_irc("charlie").await;

        server
            .write_all(b":srv 433 * charlie :Nickname is already in use\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            tokio::time::Duration::from_millis(400),
            server.read(&mut buf),
        )
        .await
        .expect("timeout waiting for NICK retry")
        .unwrap_or(0);

        let wire = String::from_utf8_lossy(&buf[..n]);
        assert!(
            wire.contains("NICK charlie1"),
            "expected NICK charlie1, got:\n{wire}"
        );
    }

    /// After 6 consecutive 433s (exceeding the 5-retry cap), run_irc should
    /// emit Event::Disconnected rather than looping forever.
    #[tokio::test]
    async fn nick_in_use_too_many_retries_disconnects() {
        let (mut server, mut events, _cmd) = start_run_irc("dave").await;

        // Send 6 × 433.  run_irc allows up to 5 retries; the 6th hits the
        // `give up` branch and emits Disconnected.
        for i in 0..6u8 {
            let nick_attempt = if i == 0 {
                "dave".to_string()
            } else {
                format!("dave{i}")
            };
            let line = format!(":srv 433 * {nick_attempt} :Nickname is already in use\r\n");
            server.write_all(line.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
            // Small pause so run_irc's select! can process each line.
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        let got_disconnect = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            while let Some(ev) = events.recv().await {
                if matches!(ev, Event::Disconnected { .. }) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        assert!(
            got_disconnect,
            "expected Event::Disconnected after 6 nick-in-use errors"
        );
    }

    // ── 904 SASL failure ─────────────────────────────────────────────────────

    /// 904 must emit Event::AuthFailed and send CAP END so the server can
    /// finish registration (without CAP END the session hangs).
    #[tokio::test]
    async fn sasl_904_emits_auth_failed_and_sends_cap_end() {
        let (mut server, mut events, _cmd) = start_run_irc("eve").await;

        server
            .write_all(b":srv 904 eve :SASL authentication failed\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Collect the AuthFailed event.
        let got_auth_failed =
            tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
                while let Some(ev) = events.recv().await {
                    if matches!(ev, Event::AuthFailed { .. }) {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);

        assert!(got_auth_failed, "expected Event::AuthFailed after 904");

        // run_irc must also send CAP END on the wire.
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            tokio::time::Duration::from_millis(400),
            server.read(&mut buf),
        )
        .await
        .expect("timeout waiting for CAP END")
        .unwrap_or(0);

        let wire = String::from_utf8_lossy(&buf[..n]);
        assert!(
            wire.contains("CAP END"),
            "expected CAP END after 904, got:\n{wire}"
        );
    }

    // ── execute_command wire formatting ──────────────────────────────────────

    /// Command::Raw strips \r, \n, and \0 to prevent protocol injection.
    #[tokio::test]
    async fn raw_command_strips_injection_chars() {
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::Raw("PRIVMSG #ch :hello\r\nEVIL LINE\0".to_string());
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .expect("execute_command");

        let wire = String::from_utf8(buf).expect("utf8");
        // Injected \r, inner \n, and \0 must be stripped from the payload.
        // Only the appended CRLF terminator from execute_command itself
        // may remain.
        let payload = wire.trim_end_matches("\r\n");
        assert!(
            !payload.contains('\r'),
            "\\r must be stripped from payload, got:\n{wire:?}"
        );
        assert!(
            !payload.contains('\n'),
            "\\n must be stripped from payload, got:\n{wire:?}"
        );
        assert!(!wire.contains('\0'), "\\0 must be stripped, got:\n{wire:?}");
        // The sanitised content must still be present.
        assert!(
            wire.contains("PRIVMSG #ch :helloEVIL LINE"),
            "sanitised body missing, got:\n{wire}"
        );
    }

    /// Command::Privmsg without a signing key writes a plain
    /// "PRIVMSG <target> :<text>\r\n" line with no tag prefix.
    #[tokio::test]
    async fn privmsg_without_signing_key_is_plain_wire() {
        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::Privmsg {
            target: "#general".to_string(),
            text: "hello world".to_string(),
            tags: HashMap::new(),
        };
        execute_command(&mut buf, cmd, &None, &None, true)
            .await
            .expect("execute_command");

        let wire = String::from_utf8(buf).expect("utf8");
        assert_eq!(
            wire, "PRIVMSG #general :hello world\r\n",
            "unsigned PRIVMSG must be a bare line, got:\n{wire:?}"
        );
    }

    /// Command::Privmsg with a signing key prepends a @+freeq.at/sig=... tag.
    #[tokio::test]
    async fn privmsg_with_signing_key_adds_sig_tag() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::ed25519::signature::rand_core::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let key_pub = key.verifying_key();
        let did = Some("did:plc:testuser".to_string());

        let mut buf: Vec<u8> = Vec::new();
        let cmd = Command::Privmsg {
            target: "#secret".to_string(),
            text: "signed message".to_string(),
            tags: HashMap::new(),
        };
        execute_command(&mut buf, cmd, &Some(key), &did, true)
            .await
            .expect("execute_command");

        let wire = String::from_utf8(buf).expect("utf8");
        assert!(
            wire.contains("PRIVMSG #secret :signed message"),
            "target and body must be present, got:\n{wire:?}"
        );

        // And the signature verifies against the document a receiver would
        // rebuild from this very line — no clock, no guessing.
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        let sig_tag = sent.tags.get("+freeq.at/sig").expect("sig tag");
        let event_id = sent
            .tags
            .get(crate::chatsig::EVENT_ID_TAG)
            .expect("the id the signature covers travels with it");
        let venue = crate::chatsig::channel_venue("#secret");
        crate::chatsig::ChatDoc::message(
            did.as_deref().unwrap(),
            event_id,
            &venue,
            "signed message",
        )
        .verify(sig_tag, &key_pub)
        .expect("signature verifies over the document");
    }

    /// A DM to a resolved DID is signed under the sorted-pair venue, which
    /// both ends and any peer can rebuild. A DM to a bare nick is sent
    /// unsigned: a nick is not a venue, and signing a guess would look like
    /// tampering to whoever checked it.
    #[tokio::test]
    async fn a_dm_is_signed_only_when_the_venue_is_knowable() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[5u8; 32]);
        let did = Some("did:plc:sender".to_string());

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Privmsg {
                target: "did:plc:peer".to_string(),
                text: "for your eyes only".to_string(),
                tags: HashMap::new(),
            },
            &Some(key.clone()),
            &did,
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        let sig_tag = sent.tags.get("+freeq.at/sig").expect("DM is signed");
        let event_id = sent.tags.get(crate::chatsig::EVENT_ID_TAG).unwrap();
        let venue = crate::chatsig::dm_venue("did:plc:sender", "did:plc:peer");
        crate::chatsig::ChatDoc::message("did:plc:sender", event_id, &venue, "for your eyes only")
            .verify(sig_tag, &key.verifying_key())
            .expect("a DM binds the sorted DID pair");

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Privmsg {
                target: "bob".to_string(),
                text: "who are you, really".to_string(),
                tags: HashMap::new(),
            },
            &Some(key),
            &did,
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        assert_eq!(
            wire, "PRIVMSG bob :who are you, really\r\n",
            "an unresolvable peer means unsigned, not signed-with-a-guess"
        );
    }

    /// A delete and both halves of a reaction are signed over the mutation
    /// document, with the event id the signature covers riding alongside.
    #[tokio::test]
    async fn a_delete_and_a_reaction_are_signed_over_the_mutation_document() {
        use crate::chatsig::Mutation;
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[8u8; 32]);
        let did = "did:plc:mutator";
        let root = "01ROOTMSGID0000000000000BB";

        // (tags as a client sends them, expected kind, expected emoji)
        let cases: Vec<(HashMap<String, String>, Mutation, Option<&str>)> = vec![
            (
                HashMap::from([("+draft/delete".to_string(), root.to_string())]),
                Mutation::Delete,
                None,
            ),
            (
                HashMap::from([
                    ("+react".to_string(), "👍".to_string()),
                    ("+reply".to_string(), root.to_string()),
                ]),
                Mutation::React,
                Some("👍"),
            ),
            (
                HashMap::from([
                    ("+freeq.at/unreact".to_string(), "👍".to_string()),
                    ("+reply".to_string(), root.to_string()),
                ]),
                Mutation::Unreact,
                Some("👍"),
            ),
        ];

        for (tags, kind, emoji) in cases {
            let mut buf: Vec<u8> = Vec::new();
            execute_command(
                &mut buf,
                Command::Tagmsg {
                    target: "#room".to_string(),
                    tags,
                },
                &Some(key.clone()),
                &Some(did.to_string()),
                true,
            )
            .await
            .unwrap();

            let wire = String::from_utf8(buf).unwrap();
            let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
            assert_eq!(sent.command, "TAGMSG");
            let sig_tag = sent
                .tags
                .get(crate::sigtag::SIG_TAG)
                .unwrap_or_else(|| panic!("{kind:?} must be signed: {wire}"));
            let event_id = sent
                .tags
                .get(crate::chatsig::EVENT_ID_TAG)
                .expect("the id the signature covers travels with it");

            let venue = crate::chatsig::channel_venue("#room");
            let mut doc = crate::chatsig::ChatDoc::mutation(kind, did, event_id, &venue, root);
            if let Some(emoji) = emoji {
                doc = doc.with_emoji(emoji);
            }
            doc.verify(sig_tag, &key.verifying_key())
                .unwrap_or_else(|e| panic!("{kind:?} signature does not verify: {e}"));
        }
    }

    /// Ephemera stay unsigned: a typing notice asserts nothing durable under
    /// anyone's name, and a signature over a keystroke is noise a verifier
    /// would have to keep forever.
    #[tokio::test]
    async fn ephemeral_tagmsgs_are_not_signed() {
        use ed25519_dalek::SigningKey;

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Tagmsg {
                target: "#room".to_string(),
                tags: HashMap::from([("+typing".to_string(), "active".to_string())]),
            },
            &Some(SigningKey::from_bytes(&[8u8; 32])),
            &Some("did:plc:mutator".to_string()),
            true,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert!(!sent.tags.contains_key(crate::sigtag::SIG_TAG), "{wire}");
        assert!(
            !sent.tags.contains_key(crate::chatsig::EVENT_ID_TAG),
            "{wire}"
        );
    }

    /// The gate covers mutations exactly as it covers messages: against a
    /// server that doesn't verify documents, a delete is the line a legacy
    /// client sends.
    #[tokio::test]
    async fn a_mutation_is_unsigned_against_a_server_that_does_not_verify() {
        use ed25519_dalek::SigningKey;

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Tagmsg {
                target: "#room".to_string(),
                tags: HashMap::from([(
                    "+draft/delete".to_string(),
                    "01ROOTMSGID0000000000000CC".to_string(),
                )]),
            },
            &Some(SigningKey::from_bytes(&[8u8; 32])),
            &Some("did:plc:mutator".to_string()),
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "@+draft/delete=01ROOTMSGID0000000000000CC TAGMSG #room\r\n"
        );
    }

    /// A mutation in a DM to a bare nick has no venue any verifier could
    /// rebuild — so it goes out unsigned rather than signed over a guess,
    /// the same rule messages follow.
    #[tokio::test]
    async fn a_mutation_to_a_bare_nick_is_unsigned() {
        use ed25519_dalek::SigningKey;

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Tagmsg {
                target: "bob".to_string(),
                tags: HashMap::from([(
                    "+draft/delete".to_string(),
                    "01ROOTMSGID0000000000000DD".to_string(),
                )]),
            },
            &Some(SigningKey::from_bytes(&[8u8; 32])),
            &Some("did:plc:mutator".to_string()),
            true,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert!(!sent.tags.contains_key(crate::sigtag::SIG_TAG), "{wire}");
    }

    /// The cap is asked for when the server offers it, and not otherwise —
    /// requesting a cap a server never advertised makes it NAK the whole REQ,
    /// which would cost every other capability too.
    #[tokio::test]
    async fn the_signing_cap_is_requested_only_when_the_server_offers_it() {
        async fn requested(advertised: &str) -> String {
            let caps_acked: CapsAcked = Arc::new(parking_lot::Mutex::new(CapsState::default()));
            let msg = Message::parse(&format!(":srv CAP * LS :{advertised}")).unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut sasl = false;
            handle_cap_response(&msg, &None, &None, &mut buf, &mut sasl, &caps_acked)
                .await
                .unwrap();
            String::from_utf8(buf).unwrap()
        }

        assert!(
            requested("message-tags server-time freeq.at/msgsig")
                .await
                .contains(MSGSIG_CAP),
            "a server that verifies documents is asked for the cap"
        );
        let legacy = requested("message-tags server-time").await;
        assert!(
            !legacy.contains(MSGSIG_CAP),
            "and one that doesn't advertise it is never asked: {legacy}"
        );
        assert!(
            legacy.contains("message-tags"),
            "the rest still goes: {legacy}"
        );
    }

    /// Against a server that never negotiated `freeq.at/msgsig`, an updated
    /// client is byte-identical to an old one: no signature, no minted id.
    /// That server would strip the signature and re-sign the message itself,
    /// turning our non-repudiable claim into its own attestation — and it
    /// ignores the id while the tag rides on over federation.
    #[tokio::test]
    async fn a_server_that_does_not_verify_documents_gets_no_signature_and_no_id() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let did = Some("did:plc:gated".to_string());

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Privmsg {
                target: "#legacy".to_string(),
                text: "same as it ever was".to_string(),
                tags: HashMap::new(),
            },
            &Some(key.clone()),
            &did,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "PRIVMSG #legacy :same as it ever was\r\n",
            "a legacy server must see exactly what a legacy client sends"
        );

        // The same send against a server that does verify: signed, with the
        // id the signature covers. Only the cap differs.
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Privmsg {
                target: "#legacy".to_string(),
                text: "same as it ever was".to_string(),
                tags: HashMap::new(),
            },
            &Some(key),
            &did,
            true,
        )
        .await
        .unwrap();
        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        assert!(sent.tags.contains_key(crate::sigtag::SIG_TAG));
        assert!(sent.tags.contains_key(crate::chatsig::EVENT_ID_TAG));
    }

    /// A tagged send (a reply, a coordination event) is signed too, and the
    /// signature covers the tags — sanitizing one in flight has to break it.
    #[tokio::test]
    async fn a_tagged_message_is_signed_over_its_tags() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[6u8; 32]);
        let did = "did:plc:tagger";
        let mut tags = HashMap::new();
        tags.insert(
            "+reply".to_string(),
            "01ROOTMSGID0000000000000AA".to_string(),
        );
        tags.insert("+freeq.at/event".to_string(), "task_result".to_string());

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            Command::Privmsg {
                target: "#swarm".to_string(),
                text: "done".to_string(),
                tags,
            },
            &Some(key.clone()),
            &Some(did.to_string()),
            true,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(buf).unwrap();
        let sent = crate::irc::Message::parse(wire.trim_end()).expect("parses");
        let sig_tag = sent.tags.get("+freeq.at/sig").unwrap();
        let event_id = sent.tags.get(crate::chatsig::EVENT_ID_TAG).unwrap();
        let venue = crate::chatsig::channel_venue("#swarm");

        let covered = crate::chatsig::ChatDoc::message(did, event_id, &venue, "done")
            .with_reply("01ROOTMSGID0000000000000AA")
            .with_coord([("+freeq.at/event", "task_result")]);
        covered
            .verify(sig_tag, &key.verifying_key())
            .expect("reply and coordination tags are covered");

        // Drop the coordination tag on the way through: the signature fails,
        // which is the whole point of covering it.
        let sanitized = crate::chatsig::ChatDoc::message(did, event_id, &venue, "done")
            .with_reply("01ROOTMSGID0000000000000AA");
        assert!(sanitized.verify(sig_tag, &key.verifying_key()).is_err());
    }

    // ── JOIN and PART events ──────────────────────────────────────────────────

    /// JOIN from another user emits Event::Joined with correct nick + channel.
    #[tokio::test]
    async fn server_join_emits_joined_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host").await;

        server
            .write_all(b":guest!u@h JOIN #lobby\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Joined { nick, channel, .. } = ev {
                    return Some((nick, channel));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, channel) = got.expect("expected Joined event");
        assert_eq!(nick, "guest");
        assert_eq!(channel, "#lobby");
    }

    /// PART emits Event::Parted with correct nick + channel.
    #[tokio::test]
    async fn server_part_emits_parted_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host2").await;

        server
            .write_all(b":leaver!u@h PART #lobby :bye\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Parted { nick, channel } = ev {
                    return Some((nick, channel));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, channel) = got.expect("expected Parted event");
        assert_eq!(nick, "leaver");
        assert_eq!(channel, "#lobby");
    }

    // ── EOF / disconnect ──────────────────────────────────────────────────────

    /// Closing the server-side of the duplex (EOF) must produce
    /// Event::Disconnected so callers know to reconnect.
    #[tokio::test]
    async fn server_eof_emits_disconnected_event() {
        let (server, mut events, _cmd) = start_run_irc("eof_test").await;

        // Drop the server side → run_irc sees EOF on read.
        drop(server);

        let got_disconnect = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            while let Some(ev) = events.recv().await {
                if matches!(ev, Event::Disconnected { .. }) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        assert!(got_disconnect, "expected Event::Disconnected on server EOF");
    }

    // ── NICK change ───────────────────────────────────────────────────────────

    /// NICK from another user emits Event::NickChanged with correct
    /// old_nick (parsed from the prefix) and new_nick (from params).
    #[tokio::test]
    async fn server_nick_change_emits_nick_changed_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host").await;

        server
            .write_all(b":alice!u@h NICK :alice2\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::NickChanged { old_nick, new_nick } = ev {
                    return Some((old_nick, new_nick));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (old, new) = got.expect("expected NickChanged event");
        assert_eq!(old, "alice");
        assert_eq!(new, "alice2");
    }

    /// A NICK message whose prefix has no user@host hostmask (bare nick prefix)
    /// must still parse correctly — old_nick from prefix, new_nick from params.
    #[tokio::test]
    async fn server_nick_change_bare_prefix_parses_correctly() {
        let (mut server, mut events, _cmd) = start_run_irc("host2").await;

        // Bare prefix: no "!user@host" component.
        server.write_all(b":bob NICK :robert\r\n").await.unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::NickChanged { old_nick, new_nick } = ev {
                    return Some((old_nick, new_nick));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (old, new) = got.expect("expected NickChanged event with bare prefix");
        assert_eq!(old, "bob");
        assert_eq!(new, "robert");
    }

    // ── QUIT ──────────────────────────────────────────────────────────────────

    /// QUIT emits Event::UserQuit with the correct nick and reason.
    #[tokio::test]
    async fn server_quit_emits_user_quit_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host3").await;

        server
            .write_all(b":bob!u@h QUIT :Gone fishing\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::UserQuit { nick, reason } = ev {
                    return Some((nick, reason));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, reason) = got.expect("expected UserQuit event");
        assert_eq!(nick, "bob");
        assert_eq!(reason, "Gone fishing");
    }

    /// QUIT with no reason parameter must not panic and must emit an empty reason.
    #[tokio::test]
    async fn server_quit_with_no_reason_emits_empty_reason() {
        let (mut server, mut events, _cmd) = start_run_irc("host4").await;

        server.write_all(b":carol!u@h QUIT\r\n").await.unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::UserQuit { nick, reason } = ev {
                    return Some((nick, reason));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, reason) = got.expect("expected UserQuit even without reason");
        assert_eq!(nick, "carol");
        assert_eq!(reason, "", "reason should be empty when param is absent");
    }

    // ── KICK ──────────────────────────────────────────────────────────────────

    /// KICK emits Event::Kicked with channel, kicked nick, kicker, and reason.
    #[tokio::test]
    async fn server_kick_emits_kicked_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host5").await;

        server
            .write_all(b":op!u@h KICK #room victim :no spam\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Kicked {
                    channel,
                    nick,
                    by,
                    reason,
                } = ev
                {
                    return Some((channel, nick, by, reason));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (channel, nick, by, reason) = got.expect("expected Kicked event");
        assert_eq!(channel, "#room");
        assert_eq!(nick, "victim");
        assert_eq!(by, "op");
        assert_eq!(reason, "no spam");
    }

    /// KICK with no reason param must emit an empty reason string, not panic.
    #[tokio::test]
    async fn server_kick_with_no_reason_emits_empty_reason() {
        let (mut server, mut events, _cmd) = start_run_irc("host6").await;

        server
            .write_all(b":op!u@h KICK #room victim\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Kicked { reason, .. } = ev {
                    return Some(reason);
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let reason = got.expect("expected Kicked event without reason");
        assert_eq!(reason, "", "reason should be empty when omitted");
    }

    // ── AWAY ──────────────────────────────────────────────────────────────────

    /// AWAY with a message emits Event::AwayChanged with away_msg = Some(…).
    #[tokio::test]
    async fn server_away_with_message_emits_away_changed() {
        let (mut server, mut events, _cmd) = start_run_irc("host7").await;

        server
            .write_all(b":dave!u@h AWAY :be right back\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::AwayChanged { nick, away_msg } = ev {
                    return Some((nick, away_msg));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, away_msg) = got.expect("expected AwayChanged event");
        assert_eq!(nick, "dave");
        assert_eq!(away_msg.as_deref(), Some("be right back"));
    }

    /// AWAY with no params emits Event::AwayChanged with away_msg = None
    /// (the user is returning from away status).
    #[tokio::test]
    async fn server_away_with_no_message_emits_away_changed_none() {
        let (mut server, mut events, _cmd) = start_run_irc("host8").await;

        server.write_all(b":dave!u@h AWAY\r\n").await.unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::AwayChanged { nick, away_msg } = ev {
                    return Some((nick, away_msg));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, away_msg) = got.expect("expected AwayChanged event for returning user");
        assert_eq!(nick, "dave");
        assert!(
            away_msg.is_none(),
            "away_msg should be None when returning from away"
        );
    }

    // ── MARKREAD (draft/read-marker) ──────────────────────────────────────────

    /// `MARKREAD <target> timestamp=<iso>` emits Event::ReadMarker with the
    /// timestamp parsed out of the `timestamp=` prefix.
    #[tokio::test]
    async fn server_markread_with_timestamp_emits_read_marker() {
        let (mut server, mut events, _cmd) = start_run_irc("rm1").await;

        server
            .write_all(b"MARKREAD #room timestamp=2026-07-02T10:00:00.000Z\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::ReadMarker { target, timestamp } = ev {
                    return Some((target, timestamp));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (target, timestamp) = got.expect("expected ReadMarker event");
        assert_eq!(target, "#room");
        assert_eq!(timestamp.as_deref(), Some("2026-07-02T10:00:00.000Z"));
    }

    /// `MARKREAD <target> *` (no marker set) emits Event::ReadMarker with
    /// timestamp = None.
    #[tokio::test]
    async fn server_markread_star_emits_read_marker_none() {
        let (mut server, mut events, _cmd) = start_run_irc("rm2").await;

        server.write_all(b"MARKREAD #room *\r\n").await.unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::ReadMarker { target, timestamp } = ev {
                    return Some((target, timestamp));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (target, timestamp) = got.expect("expected ReadMarker event");
        assert_eq!(target, "#room");
        assert!(timestamp.is_none(), "star means no marker → None");
    }

    /// The outbound `mark_read` helper writes a well-formed MARKREAD set line.
    #[tokio::test]
    async fn mark_read_writes_markread_set_line() {
        let (mut server, _events, cmd) = start_run_irc("rm3").await;

        // Registration gates outbound commands; send 001 so the queue flushes.
        server
            .write_all(b":srv 001 rm3 :Welcome\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        cmd.send(Command::Raw(
            "MARKREAD #room timestamp=2026-07-02T10:00:00.000Z".to_string(),
        ))
        .await
        .unwrap();

        let mut buf = vec![0u8; 512];
        let mut wire = String::new();
        for _ in 0..5 {
            if let Ok(Ok(n)) = tokio::time::timeout(
                tokio::time::Duration::from_millis(300),
                server.read(&mut buf),
            )
            .await
            {
                wire.push_str(&String::from_utf8_lossy(&buf[..n]));
                if wire.contains("MARKREAD") {
                    break;
                }
            }
        }
        assert!(
            wire.contains("MARKREAD #room timestamp=2026-07-02T10:00:00.000Z"),
            "expected MARKREAD set line in:\n{wire}"
        );
    }

    // ── TOPIC ─────────────────────────────────────────────────────────────────

    /// Live TOPIC change emits Event::TopicChanged with channel, new topic,
    /// and set_by = Some(nick parsed from prefix).
    #[tokio::test]
    async fn server_topic_change_emits_topic_changed_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host9").await;

        server
            .write_all(b":mod!u@h TOPIC #room :New topic here\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::TopicChanged {
                    channel,
                    topic,
                    set_by,
                } = ev
                {
                    return Some((channel, topic, set_by));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (channel, topic, set_by) = got.expect("expected TopicChanged event");
        assert_eq!(channel, "#room");
        assert_eq!(topic, "New topic here");
        assert_eq!(set_by.as_deref(), Some("mod"));
    }

    /// 332 RPL_TOPIC (received on join) emits Event::TopicChanged with
    /// set_by = None (the server doesn't tell us who set it in 332 itself).
    #[tokio::test]
    async fn server_rpl_topic_332_emits_topic_changed_no_setter() {
        let (mut server, mut events, _cmd) = start_run_irc("host10").await;

        // 332 format: :<server> 332 <ournick> <channel> :<topic>
        server
            .write_all(b":srv 332 host10 #room :Welcome to the room\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::TopicChanged {
                    channel,
                    topic,
                    set_by,
                } = ev
                {
                    return Some((channel, topic, set_by));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (channel, topic, set_by) = got.expect("expected TopicChanged from 332");
        assert_eq!(channel, "#room");
        assert_eq!(topic, "Welcome to the room");
        assert!(
            set_by.is_none(),
            "set_by should be None for 332 RPL_TOPIC (no setter in that numeric)"
        );
    }

    // ── INVITE ────────────────────────────────────────────────────────────────

    /// INVITE emits Event::Invited with the channel and the inviter's nick.
    #[tokio::test]
    async fn server_invite_emits_invited_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host11").await;

        // INVITE <target_nick> <channel>
        server
            .write_all(b":alice!u@h INVITE host11 #secret\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Invited { channel, by } = ev {
                    return Some((channel, by));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (channel, by) = got.expect("expected Invited event");
        assert_eq!(channel, "#secret");
        assert_eq!(by, "alice");
    }

    // ── NAMES / 353 ───────────────────────────────────────────────────────────

    /// 353 RPL_NAMREPLY emits Event::Names with the correct channel and nicks.
    #[tokio::test]
    async fn server_353_emits_names_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host12").await;

        // 353 format: :<server> 353 <ournick> = <channel> :<nick1> <nick2> …
        server
            .write_all(b":srv 353 host12 = #room :alice @bob +carol\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Names { channel, nicks } = ev {
                    return Some((channel, nicks));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (channel, nicks) = got.expect("expected Names event");
        assert_eq!(channel, "#room");
        assert_eq!(nicks, vec!["alice", "@bob", "+carol"]);
    }

    // ── TAGMSG dispatch ───────────────────────────────────────────────────────

    /// TAGMSG emits Event::TagMsg with the correct from, target, and tags.
    #[tokio::test]
    async fn server_tagmsg_emits_tag_msg_event() {
        let (mut server, mut events, _cmd) = start_run_irc("host13").await;

        // Tagged TAGMSG: @+react=👍 :alice!u@h TAGMSG #room
        server
            .write_all(b"@+react=\xf0\x9f\x91\x8d :alice!u@h TAGMSG #room\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::TagMsg {
                    from, target, tags, ..
                } = ev
                {
                    return Some((from, target, tags));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (from, target, tags) = got.expect("expected TagMsg event");
        assert_eq!(from, "alice");
        assert_eq!(target, "#room");
        assert_eq!(tags.get("+react").map(|s| s.as_str()), Some("👍"));
    }

    /// A task event arrives as `Event::Act` beside the raw TAGMSG, read once
    /// so a consumer does not have to know the tag names.
    #[tokio::test]
    async fn server_act_tagmsg_emits_an_act_event_beside_the_tagmsg() {
        let (mut server, mut events, _cmd) = start_run_irc("host30").await;

        server
            .write_all(
                b"@+freeq.at/act=handoff;+freeq.at/act-verb=offer;\
+freeq.at/act-title=Cite\\s3\\ssources;+freeq.at/from=did:plc:eliza;\
+freeq.at/eventid=01OFFER :eliza!u@h TAGMSG #room\r\n",
            )
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (mut act, mut raw) = (None, None);
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                match ev {
                    Event::Act { .. } => act = Some(ev),
                    Event::TagMsg { tags, .. } => raw = Some(tags),
                    _ => {}
                }
                if act.is_some() && raw.is_some() {
                    return;
                }
            }
        })
        .await;

        let Some(Event::Act {
            from,
            target,
            kind,
            verb,
            did,
            task_id,
            fields,
            ..
        }) = act
        else {
            panic!("expected an Act event");
        };
        assert_eq!(from, "eliza");
        assert_eq!(target, "#room");
        assert_eq!(verb, "offer");
        assert_eq!(kind, "handoff");
        assert_eq!(did.as_deref(), Some("did:plc:eliza"));
        // An opener names no other action, so it names itself.
        assert_eq!(task_id, "01OFFER");
        assert_eq!(
            fields.get("act-title").map(String::as_str),
            Some("Cite 3 sources")
        );
        // The raw line still arrives, the way a coordination TAGMSG does.
        let raw = raw.expect("the TAGMSG must still arrive");
        assert_eq!(
            raw.get("+freeq.at/act-verb").map(|s| s.as_str()),
            Some("offer")
        );
    }

    /// Our own event, echoed back by a server that acked `echo-message`, is
    /// one event. Same id, no `time` tag — the live case, where the replay
    /// test below is the history one. Both reach the same sighting check;
    /// this pins the one a sender meets first.
    #[tokio::test]
    async fn our_own_echoed_task_event_is_handed_up_once() {
        let (mut server, mut events, _cmd) = start_run_irc("host32").await;

        let line: &[u8] = b"@+freeq.at/act=handoff;+freeq.at/act-verb=offer;\
+freeq.at/act-title=ship\\sit;+freeq.at/from=did:plc:eliza;\
+freeq.at/eventid=01ECHO :eliza!u@h TAGMSG #room\r\n";
        server.write_all(line).await.unwrap();
        server.write_all(line).await.unwrap();
        // A different event after it, so an empty second sighting cannot be
        // mistaken for one that simply had not arrived yet.
        server
            .write_all(
                b"@+freeq.at/act=handoff;+freeq.at/act-verb=claim;\
+freeq.at/act-id=01ECHO;+freeq.at/from=did:plc:scholar;\
+freeq.at/eventid=01AFTER :scholar!u@h TAGMSG #room\r\n",
            )
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut seen: Vec<(String, bool)> = Vec::new();
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Act {
                    event_id, replayed, ..
                } = ev
                {
                    let last = event_id == "01AFTER";
                    seen.push((event_id, replayed));
                    if last {
                        return;
                    }
                }
            }
        })
        .await;

        assert_eq!(
            seen.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec!["01ECHO", "01AFTER"],
            "the echo must be handed up once"
        );
        assert!(
            seen.iter().all(|(_, replayed)| !replayed),
            "a line with no time tag is live, not a replay"
        );
    }

    /// The same event twice — a joiner's replay and the history it asks for
    /// next — is one event. The TAGMSG still arrives both times: it is the
    /// line, not the event.
    #[tokio::test]
    async fn an_act_event_seen_twice_is_handed_up_once() {
        let (mut server, mut events, _cmd) = start_run_irc("host31").await;

        let line: &[u8] = b"@time=2026-08-22T10:00:00.000Z;+freeq.at/act=handoff;\
+freeq.at/act-verb=claim;+freeq.at/act-id=01OFFER;+freeq.at/from=did:plc:scholar;\
+freeq.at/eventid=01CLAIM :scholar!u@h TAGMSG #room\r\n";
        server.write_all(line).await.unwrap();
        server.write_all(line).await.unwrap();
        // A second, different event: it must still come through, and it is
        // also what tells us the first one's duplicate was really dropped
        // rather than merely slow.
        server
            .write_all(
                b"@+freeq.at/act=handoff;+freeq.at/act-verb=progress;\
+freeq.at/act-id=01OFFER;+freeq.at/from=did:plc:scholar;\
+freeq.at/eventid=01PROGRESS :scholar!u@h TAGMSG #room\r\n",
            )
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut seen: Vec<(String, String, bool)> = Vec::new();
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Act {
                    event_id,
                    task_id,
                    replayed,
                    ..
                } = ev
                {
                    let last = event_id == "01PROGRESS";
                    seen.push((event_id, task_id, replayed));
                    if last {
                        return;
                    }
                }
            }
        })
        .await;

        assert_eq!(
            seen.iter()
                .map(|(id, _, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["01CLAIM", "01PROGRESS"],
            "the replayed claim must be handed up once"
        );
        assert!(seen[0].2, "a line carrying a time tag is a replay");
        assert!(!seen[1].2);
        assert_eq!(seen[1].1, "01OFFER", "a follow-up names its task");
    }

    // ── legacy +freeq.at/multiline \\n normalization ──────────────────────────

    /// PRIVMSG bearing the legacy `+freeq.at/multiline` tag must have its
    /// literal `\n` escape sequences (two chars: backslash + n) replaced with
    /// real newline characters before the Event::Message is emitted.
    #[tokio::test]
    async fn legacy_multiline_tag_normalizes_slash_n_to_newline() {
        let (mut server, mut events, _cmd) = start_run_irc("host14").await;

        // The wire body contains literal \n (backslash + 'n'), not a real newline.
        server
            .write_all(
                b"@+freeq.at/multiline=1 :alice!u@h PRIVMSG #room :line1\\nline2\\nline3\r\n",
            )
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Message { text, .. } = ev {
                    return Some(text);
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let text = got.expect("expected Message event");
        assert_eq!(
            text, "line1\nline2\nline3",
            "legacy \\n escape must be replaced with a real newline"
        );
    }

    /// A PRIVMSG without the `+freeq.at/multiline` tag must NOT have `\n`
    /// sequences replaced — the body should be delivered verbatim.
    #[tokio::test]
    async fn privmsg_without_multiline_tag_preserves_literal_slash_n() {
        let (mut server, mut events, _cmd) = start_run_irc("host15").await;

        server
            .write_all(b":alice!u@h PRIVMSG #room :keep\\nraw\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Message { text, .. } = ev {
                    return Some(text);
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let text = got.expect("expected Message event");
        assert_eq!(
            text, r"keep\nraw",
            "without multiline tag, literal \\n must be preserved"
        );
    }

    // ── extended-join account field ───────────────────────────────────────────

    /// Extended JOIN with a DID account field emits Event::Joined with
    /// account = Some(did).
    #[tokio::test]
    async fn extended_join_with_did_account_emits_joined_with_account() {
        let (mut server, mut events, _cmd) = start_run_irc("host16").await;

        // extended-join: JOIN <channel> <account> :<realname>
        server
            .write_all(b":alice!u@h JOIN #lobby did:plc:abc123 :Alice Smith\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Joined {
                    nick,
                    channel,
                    account,
                } = ev
                {
                    return Some((nick, channel, account));
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let (nick, channel, account) = got.expect("expected Joined event with account");
        assert_eq!(nick, "alice");
        assert_eq!(channel, "#lobby");
        assert_eq!(
            account.as_deref(),
            Some("did:plc:abc123"),
            "DID account must be present in extended JOIN"
        );
    }

    /// Extended JOIN where account is the unauthenticated sentinel `*` must
    /// emit Event::Joined with account = None.
    #[tokio::test]
    async fn extended_join_with_star_account_emits_joined_no_account() {
        let (mut server, mut events, _cmd) = start_run_irc("host17").await;

        server
            .write_all(b":guest!u@h JOIN #lobby * :Guest User\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let got = tokio::time::timeout(tokio::time::Duration::from_millis(400), async {
            while let Some(ev) = events.recv().await {
                if let Event::Joined { account, .. } = ev {
                    return Some(account);
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        let account = got.expect("expected Joined event");
        assert!(
            account.is_none(),
            "account `*` sentinel must be treated as unauthenticated (None)"
        );
    }
}

#[cfg(test)]
mod did_maps_tests {
    use super::*;

    const BOB: &str = "did:plc:bob";

    #[test]
    fn learn_reports_new_and_changed_bindings_only() {
        let mut m = DidMapsState::default();
        assert!(m.learn("Bob", BOB)); // new
        assert!(!m.learn("bob", BOB)); // same (case-insensitive nick)
        assert!(m.learn("bob", "did:plc:other")); // changed
    }

    #[test]
    fn learn_display_never_creates_an_addressing_binding() {
        let mut m = DidMapsState::default();
        m.learn_display(BOB, "bob");
        assert_eq!(m.wire_target("bob"), "bob"); // strict: unresolved
        assert_eq!(m.dm_key("bob"), BOB); // loose: display reverse applies
    }

    #[test]
    fn forget_nick_clears_addressing_but_keeps_display() {
        let mut m = DidMapsState::default();
        m.learn("bob", BOB);
        m.forget_nick("bob");
        assert_eq!(m.wire_target("bob"), "bob"); // routing must not follow
        assert_eq!(m.dm_key("bob"), BOB); // thread key survives the quit
        assert_eq!(m.did_to_nick.get(BOB).map(String::as_str), Some("bob"));
    }

    #[test]
    fn rename_moves_the_binding() {
        let mut m = DidMapsState::default();
        m.learn("bob", BOB);
        m.rename("bob", "bobby");
        assert_eq!(m.wire_target("bobby"), BOB);
        assert_eq!(m.wire_target("bob"), "bob");
        assert_eq!(m.did_to_nick.get(BOB).map(String::as_str), Some("bobby"));
    }

    #[test]
    fn keys_pass_dids_through_and_leave_guests_untouched() {
        let m = DidMapsState::default();
        assert_eq!(m.dm_key(BOB), BOB);
        assert_eq!(m.dm_key("Guest7"), "Guest7"); // no mangling
        assert_eq!(m.wire_target(BOB), BOB);
    }

    // ── task events ──────────────────────────────────────────────────────────

    /// A handle wired to a channel nothing reads from until the test does.
    fn task_handle() -> (ClientHandle, mpsc::Receiver<Command>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        (
            ClientHandle {
                cmd_tx,
                echo_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
                caps_acked: Arc::new(parking_lot::Mutex::new(CapsState::default())),
                did_maps: Arc::new(parking_lot::Mutex::new(DidMapsState::default())),
            },
            cmd_rx,
        )
    }

    /// Run one `send_act` against a signing session and return the id it
    /// handed back with the lines it put on the wire.
    async fn sent_act(
        tags: std::collections::HashMap<String, String>,
        human_text: Option<&'static str>,
    ) -> (Result<String>, String) {
        use ed25519_dalek::SigningKey;

        let (handle, mut cmd_rx) = task_handle();
        let sending = tokio::spawn(async move { handle.send_act("#room", tags, human_text).await });
        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(SigningKey::from_bytes(&[7u8; 32])),
            &Some("did:plc:eliza".to_string()),
            true,
        )
        .await
        .expect("the connection survives whatever the caller is told");
        (sending.await.unwrap(), String::from_utf8(buf).unwrap())
    }

    /// A kind and a verb this SDK has never heard of go out signed. Nothing in
    /// the send path reads either one — which verbs a kind allows is the rules
    /// file's business, and a new kind needs no code here at all.
    #[tokio::test]
    async fn a_kind_and_verb_the_sdk_never_heard_of_go_out_signed() {
        use ed25519_dalek::SigningKey;

        let tags = crate::act::act_tags(
            "lease",
            "renew",
            Some("01LEASE"),
            "did:plc:eliza",
            &[("term", "30d")],
        );
        let (id, wire) = sent_act(tags, None).await;
        let event_id = id.expect("the event was sent");

        let mut lines = wire.lines();
        let event = crate::irc::Message::parse(lines.next().unwrap()).expect("parses");
        assert_eq!(event.command, "TAGMSG");
        assert_eq!(
            event.tags.get("+freeq.at/act-verb").map(String::as_str),
            Some("renew")
        );
        assert_eq!(
            event.tags.get("+freeq.at/act-term").map(String::as_str),
            Some("30d")
        );
        let sig = event
            .tags
            .get(crate::sigtag::SIG_TAG)
            .unwrap_or_else(|| panic!("a task event is never sent unsigned: {wire}"));
        crate::act::verify_act(
            event.tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            &crate::chatsig::channel_venue("#room"),
            &event_id,
            sig,
            &SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
        )
        .expect("the signature verifies over the venue and the id a receiver rebuilds");

        // A verb with no sentence written for it is named, not described.
        let companion = crate::irc::Message::parse(lines.next().unwrap()).expect("parses");
        assert_eq!(
            companion.params,
            vec!["#room".to_string(), "renew".to_string()],
            "{wire}"
        );
    }

    /// With no line asked for, the companion is the one `act_line` writes for
    /// these tags, and it names the action the event is about.
    #[tokio::test]
    async fn no_line_asked_for_sends_the_one_the_tags_deserve() {
        let tags = crate::act::act_tags(
            "handoff",
            "progress",
            Some("01OFFER"),
            "did:plc:eliza",
            &[("note", "halfway")],
        );
        let (id, wire) = sent_act(tags, None).await;
        id.expect("the event was sent");

        let companion = crate::irc::Message::parse(wire.lines().nth(1).unwrap()).expect("parses");
        assert_eq!(companion.command, "PRIVMSG");
        assert_eq!(
            companion.params,
            vec!["#room".to_string(), "progress: halfway".to_string()],
            "{wire}"
        );
        assert_eq!(
            companion.tags.get("+freeq.at/ref").map(String::as_str),
            Some("01OFFER"),
            "a follow-up's companion names the action, not this event: {wire}"
        );
    }

    /// An opener names no action, so its companion names the event itself —
    /// the id every later move will carry.
    #[tokio::test]
    async fn an_openers_companion_names_the_event_it_opened() {
        let tags = crate::act::act_tags(
            "handoff",
            "offer",
            None,
            "did:plc:eliza",
            &[("title", "Cite 3 sources")],
        );
        let (id, wire) = sent_act(tags, None).await;
        let event_id = id.expect("the event was sent");

        let companion = crate::irc::Message::parse(wire.lines().nth(1).unwrap()).expect("parses");
        assert_eq!(
            companion.params,
            vec!["#room".to_string(), "offered: Cite 3 sources".to_string()]
        );
        assert_eq!(
            companion.tags.get("+freeq.at/ref").map(String::as_str),
            Some(event_id.as_str()),
            "{wire}"
        );
    }

    /// A caller who asks for no line gets the event and nothing else; one who
    /// writes their own gets exactly what they wrote.
    #[tokio::test]
    async fn the_caller_decides_whether_a_line_goes_with_it() {
        let tags =
            || crate::act::act_tags("handoff", "accept", Some("01OFFER"), "did:plc:eliza", &[]);

        let (id, silent) = sent_act(tags(), Some("")).await;
        id.expect("the event was sent");
        assert_eq!(silent.lines().count(), 1, "no companion at all: {silent}");
        assert!(silent.starts_with('@'), "{silent}");

        let (id, written) = sent_act(tags(), Some("on it")).await;
        id.expect("the event was sent");
        let companion =
            crate::irc::Message::parse(written.lines().nth(1).unwrap()).expect("parses");
        assert_eq!(
            companion.params,
            vec!["#room".to_string(), "on it".to_string()],
            "{written}"
        );
    }

    /// No key, no event. Every other send here falls back to unsigned; a task
    /// event asserts nothing without a signature, so the caller is told instead.
    #[tokio::test]
    async fn a_task_event_without_a_key_is_refused_and_nothing_is_written() {
        let (handle, mut cmd_rx) = task_handle();
        let sending = tokio::spawn(async move {
            handle
                .send_act(
                    "#room",
                    crate::act::act_tags("handoff", "claim", Some("01OFFER"), "did:plc:x", &[]),
                    None,
                )
                .await
        });

        let mut buf: Vec<u8> = Vec::new();
        execute_command(&mut buf, cmd_rx.recv().await.unwrap(), &None, &None, true)
            .await
            .expect("the connection survives a refusal");
        let refused = sending.await.unwrap().expect_err("no key, no event");
        assert_eq!(refused.to_string(), ACT_UNSIGNABLE);
        assert!(buf.is_empty(), "nothing may reach the wire unsigned");
    }

    /// A session with a key but no account is refused too. The guard names
    /// three cases — no key, no DID, or neither — and a single tuple pattern
    /// answers all three, so this is the arm the two tests either side of it
    /// leave unexercised.
    #[tokio::test]
    async fn a_task_event_from_a_session_with_no_account_is_refused() {
        use ed25519_dalek::SigningKey;

        let (handle, mut cmd_rx) = task_handle();
        let sending = tokio::spawn(async move {
            handle
                .send_act(
                    "#room",
                    crate::act::act_tags("handoff", "claim", Some("01OFFER"), "did:plc:x", &[]),
                    None,
                )
                .await
        });

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(SigningKey::from_bytes(&[3u8; 32])),
            &None,
            true,
        )
        .await
        .expect("the connection survives a refusal");
        let refused = sending.await.unwrap().expect_err("no account, no event");
        assert_eq!(refused.to_string(), ACT_UNSIGNABLE);
        assert!(buf.is_empty(), "nothing may reach the wire unsigned");
    }

    /// A bare nick has no venue any verifier could rebuild, so it has no task
    /// event either — the same refusal, for the same reason.
    #[tokio::test]
    async fn a_task_event_to_a_nick_we_hold_no_did_for_is_refused() {
        use ed25519_dalek::SigningKey;

        let (handle, mut cmd_rx) = task_handle();
        let sending = tokio::spawn(async move {
            handle
                .send_act(
                    "stranger",
                    crate::act::act_tags("handoff", "claim", Some("01OFFER"), "did:plc:x", &[]),
                    None,
                )
                .await
        });

        let mut buf: Vec<u8> = Vec::new();
        execute_command(
            &mut buf,
            cmd_rx.recv().await.unwrap(),
            &Some(SigningKey::from_bytes(&[9u8; 32])),
            &Some("did:plc:sender".to_string()),
            true,
        )
        .await
        .expect("the connection survives a refusal");
        let refused = sending.await.unwrap().expect_err("no venue, no event");
        assert_eq!(refused.to_string(), ACT_UNSIGNABLE);
        assert!(buf.is_empty(), "nothing may reach the wire unsigned");
    }

    #[test]
    fn dm_key_for_selects_the_peer_end_and_skips_channels() {
        let maps: DidMaps = Arc::new(parking_lot::Mutex::new(DidMapsState::default()));
        maps.lock().learn("bob", BOB);
        // Channel → None.
        assert_eq!(dm_key_for(&maps, "me", "bob", "#dev"), None);
        // Incoming: peer is the sender.
        assert_eq!(dm_key_for(&maps, "me", "bob", "me").as_deref(), Some(BOB));
        // Echo of our own send: peer is the target.
        assert_eq!(dm_key_for(&maps, "me", "me", "bob").as_deref(), Some(BOB));
        // Guest peer stays nick-keyed.
        assert_eq!(
            dm_key_for(&maps, "me", "guest9", "me").as_deref(),
            Some("guest9")
        );
    }
}
