//! IRCv3 `draft/multiline` support — the inbound BATCH state machine,
//! `draft/multiline` assembly per concat rules, policy limits, and the
//! outbound per-receiver wire formatting that BATCH-wraps for
//! receivers that negotiated `draft/multiline` and falls back to N
//! individual PRIVMSGs (msgid + tags on the first only) for receivers
//! that didn't.
//!
//! Spec: <https://ircv3.net/specs/extensions/multiline>

use std::collections::HashMap;

/// Server policy: maximum total byte length of a multiline batch's
/// combined message value. Spec calls this `max-bytes` and requires
/// us to advertise it.
///
/// Counted bytes per spec: only the body (last PRIVMSG/NOTICE param)
/// of each line, plus one byte per `\n` separator. Not the prefix,
/// command, target, or tags.
///
/// 40 KB is the same value the spec uses in its own examples and
/// comfortably fits any sane LLM turn (~12k words). Configurable in
/// a follow-up if needed.
pub const MAX_BYTES: usize = 40_000;

/// Server policy: maximum number of PRIVMSG/NOTICE lines in a single
/// multiline batch. Spec calls this `max-lines` (recommended).
///
/// 100 lines covers any realistic structured output (markdown with
/// headings + bullets + paragraphs) without enabling abusive batches.
pub const MAX_LINES: usize = 100;

/// Soft cap on concurrent open batches per session. The spec allows
/// multiple, but in practice clients open one at a time. Capping at
/// 5 prevents a misbehaving client from accumulating unbounded
/// per-session state by opening batches and never closing them.
pub const MAX_CONCURRENT_BATCHES_PER_SESSION: usize = 5;

/// Per-line entry inside an open batch: the body and whether this
/// line carried the `draft/multiline-concat` tag (meaning "join to
/// previous with no separator", vs. the default "join with `\n`").
#[derive(Debug, Clone)]
pub struct BatchLine {
    /// Final-param body of this PRIVMSG or NOTICE.
    pub body: String,
    /// True if this line carried `draft/multiline-concat`.
    pub concat_to_previous: bool,
    /// PRIVMSG or NOTICE — must match across the whole batch.
    pub command: String,
}

/// An open BATCH on a single connection — accumulates lines until
/// the matching `BATCH -<id>` arrives, then gets dispatched as a
/// single logical message by the batch-type-specific handler.
#[derive(Debug, Clone)]
pub struct OpenBatch {
    /// The `batch_id` parameter the client supplied (without the `+`).
    pub batch_id: String,
    /// Batch type, e.g. `draft/multiline`.
    pub batch_type: String,
    /// Target channel or nick. Every PRIVMSG inside the batch must
    /// have a target equal to this; mismatch → MULTILINE_INVALID_TARGET.
    pub target: String,
    /// Tags from the BATCH opener (other than `batch`). Per spec,
    /// client-only tags associated with the assembled message live
    /// here, not on individual PRIVMSGs inside.
    pub opener_tags: HashMap<String, String>,
    /// Accumulated lines, in arrival order.
    pub lines: Vec<BatchLine>,
    /// Running total of body bytes + 1 per `\n` separator (per spec's
    /// max-bytes accounting).
    pub byte_count: usize,
    /// First command seen inside the batch — used to enforce the
    /// "PRIVMSG-only XOR NOTICE-only" rule. Set when the first line
    /// arrives.
    pub first_command: Option<String>,
}

impl OpenBatch {
    /// Compute the byte cost a new line would add to the batch:
    /// the body length, plus 1 for the `\n` separator IF this is not
    /// the first line AND this line is NOT marked `concat-to-previous`.
    pub fn cost_of_appending(&self, body: &str, concat_to_previous: bool) -> usize {
        if self.lines.is_empty() || concat_to_previous {
            body.len()
        } else {
            body.len() + 1
        }
    }
}

/// Standard-replies error codes per the spec's "Errors" section.
/// Emitted as `FAIL BATCH <CODE> [<args>...] :<human-readable>`.
pub mod fail_code {
    pub const MULTILINE_MAX_BYTES: &str = "MULTILINE_MAX_BYTES";
    pub const MULTILINE_MAX_LINES: &str = "MULTILINE_MAX_LINES";
    pub const MULTILINE_INVALID_TARGET: &str = "MULTILINE_INVALID_TARGET";
    pub const MULTILINE_INVALID: &str = "MULTILINE_INVALID";
}

// ──────────────────────────────────────────────────────────────────
// BATCH state machine handlers
//
// These functions are intentionally pure-state — they take a
// `SharedState` and the raw inputs, mutate `state.open_batches`, and
// return success or one of the spec's MULTILINE_* error codes. The
// caller in connection/mod.rs is responsible for parsing the wire
// message and emitting `FAIL BATCH <code>` replies. Keeping the
// state mutations here makes the logic testable without any wire
// plumbing.
// ──────────────────────────────────────────────────────────────────

use std::sync::Arc;

use crate::server::SharedState;

/// Outcome of a batch operation. The `Err` variant carries the
/// `MULTILINE_*` code the caller should emit as `FAIL BATCH <code>
/// [<args>] :<reason>`. Static strings so they can be matched on by
/// tests without allocation.
pub type BatchResult<T> = Result<T, BatchError>;

#[derive(Debug, PartialEq, Eq)]
pub enum BatchError {
    /// `MULTILINE_INVALID` — anything that doesn't fit the more
    /// specific buckets (unknown batch id, blank-line rules, type
    /// mismatch within a batch, etc.).
    Invalid(&'static str),
    /// `MULTILINE_MAX_BYTES <limit>` — appending this line would
    /// blow the per-batch byte budget.
    MaxBytes,
    /// `MULTILINE_MAX_LINES <limit>` — appending this line would
    /// exceed the per-batch line count.
    MaxLines,
    /// `MULTILINE_INVALID_TARGET <batch-target> <line-target>` —
    /// a PRIVMSG within the batch had a target that doesn't match
    /// the batch's declared target.
    InvalidTarget {
        batch_target: String,
        line_target: String,
    },
}

/// Open a new BATCH on the given session. Validates the batch type
/// (only `draft/multiline` for now), checks the per-session concurrent
/// cap, and rejects duplicates of an already-open batch id.
///
/// Caller passes the tags from the BATCH opener (sans `batch`) —
/// those tags carry the client-only metadata for the assembled
/// logical message (per spec § "Message tags").
pub fn handle_batch_open(
    state: &Arc<SharedState>,
    session_id: &str,
    batch_id: &str,
    batch_type: &str,
    target: &str,
    opener_tags: HashMap<String, String>,
) -> BatchResult<()> {
    if batch_id.is_empty() {
        return Err(BatchError::Invalid("empty batch id"));
    }
    // Currently `draft/multiline` is the only inbound batch type the
    // server accepts; other future types (e.g. `draft/labeled`) would
    // land their own validators here.
    if batch_type != "draft/multiline" {
        return Err(BatchError::Invalid("unknown batch type"));
    }
    if target.is_empty() {
        return Err(BatchError::Invalid("missing batch target"));
    }

    let key = (session_id.to_string(), batch_id.to_string());
    let mut open = state.open_batches.lock();

    // Reject duplicate batch id on the same session.
    if open.contains_key(&key) {
        return Err(BatchError::Invalid("batch id already open"));
    }

    // Cap concurrent open batches per session — prevents a misbehaving
    // client from accumulating unbounded per-session state.
    if count_session_open_batches(&open, session_id) >= MAX_CONCURRENT_BATCHES_PER_SESSION {
        return Err(BatchError::Invalid("too many concurrent batches"));
    }

    open.insert(
        key,
        OpenBatch {
            batch_id: batch_id.to_string(),
            batch_type: batch_type.to_string(),
            target: target.to_string(),
            opener_tags,
            lines: Vec::new(),
            byte_count: 0,
            first_command: None,
        },
    );
    Ok(())
}

/// Outcome of a PRIVMSG/NOTICE arriving on a session: was it part of
/// an open batch (and absorbed), or should the caller dispatch it as
/// a normal standalone message?
#[derive(Debug)]
pub enum RouteOutcome {
    /// Message had a `batch=<id>` tag matching an open batch on this
    /// session, and was appended successfully. Caller should NOT
    /// dispatch it as a standalone PRIVMSG/NOTICE.
    Absorbed,
    /// No `batch` tag, or the tag pointed at an unknown batch id.
    /// Caller dispatches as a normal standalone message.
    NotInBatch,
    /// Message claimed membership in an open batch but failed
    /// validation (target mismatch, byte/line cap exceeded, blank-
    /// line concat, type mixing). Caller should emit FAIL with the
    /// supplied error and SHOULD NOT dispatch the message.
    Error(BatchError),
}

/// Route an inbound PRIVMSG/NOTICE: if it carries a `batch=<id>` tag
/// matching an open batch on this session, append it; otherwise
/// signal NotInBatch so the caller dispatches it normally.
///
/// `concat_to_previous` reflects whether the line carried the
/// `draft/multiline-concat` tag.
pub fn try_route_to_batch(
    state: &Arc<SharedState>,
    session_id: &str,
    msg_tags: &HashMap<String, String>,
    command: &str,
    target: &str,
    body: &str,
    concat_to_previous: bool,
) -> RouteOutcome {
    let batch_id = match msg_tags.get("batch") {
        Some(b) => b,
        None => return RouteOutcome::NotInBatch,
    };

    let key = (session_id.to_string(), batch_id.to_string());
    let mut open = state.open_batches.lock();
    let entry = match open.get_mut(&key) {
        Some(e) => e,
        // Per the base BATCH spec, a `batch=<id>` tag pointing at no
        // open batch is silently treated as a normal standalone
        // message (the receiver simply doesn't know about the batch).
        None => return RouteOutcome::NotInBatch,
    };

    // Validation per spec:
    // - Target must match the batch target.
    if target != entry.target {
        return RouteOutcome::Error(BatchError::InvalidTarget {
            batch_target: entry.target.clone(),
            line_target: target.to_string(),
        });
    }
    // - Batch contains only PRIVMSG or only NOTICE — first line sets
    //   the type; subsequent lines must match.
    match &entry.first_command {
        Some(seen) if seen != command => {
            return RouteOutcome::Error(BatchError::Invalid(
                "cannot mix PRIVMSG and NOTICE in a draft/multiline batch",
            ));
        }
        None => {
            entry.first_command = Some(command.to_string());
        }
        _ => {}
    }
    // - Blank line with concat tag is invalid; entirely-blank message
    //   guard is enforced at close-time.
    if concat_to_previous && body.is_empty() {
        return RouteOutcome::Error(BatchError::Invalid(
            "cannot send a blank line with the multiline concat tag",
        ));
    }
    // - First-line concat is invalid (nothing to join to).
    if entry.lines.is_empty() && concat_to_previous {
        return RouteOutcome::Error(BatchError::Invalid(
            "first line cannot carry draft/multiline-concat",
        ));
    }
    // - Byte budget.
    let cost = entry.cost_of_appending(body, concat_to_previous);
    if entry.byte_count + cost > MAX_BYTES {
        return RouteOutcome::Error(BatchError::MaxBytes);
    }
    // - Line budget (each line counts, including concat'd ones, per
    //   spec § "Batch types").
    if entry.lines.len() + 1 > MAX_LINES {
        return RouteOutcome::Error(BatchError::MaxLines);
    }

    entry.byte_count += cost;
    entry.lines.push(BatchLine {
        body: body.to_string(),
        concat_to_previous,
        command: command.to_string(),
    });
    RouteOutcome::Absorbed
}

/// Close an open BATCH and return its accumulated state to the
/// caller. `handle_batch_command`'s success arm calls
/// `dispatch_assembled_batch` on the returned value to feed the
/// assembled message back through the normal PRIVMSG/NOTICE pipeline.
///
/// Final validation: an entirely-blank batch (no lines OR every line
/// has an empty body) is rejected per spec.
pub fn handle_batch_close(
    state: &Arc<SharedState>,
    session_id: &str,
    batch_id: &str,
) -> BatchResult<OpenBatch> {
    let key = (session_id.to_string(), batch_id.to_string());
    let batch = state
        .open_batches
        .lock()
        .remove(&key)
        .ok_or(BatchError::Invalid("unknown batch id"))?;

    // Spec: "Clients MUST NOT send messages consisting entirely of
    // blank lines." Reject at close — we couldn't tell the message
    // was all-blank until now.
    let all_blank = batch.lines.iter().all(|l| l.body.is_empty());
    if !batch.lines.is_empty() && all_blank {
        return Err(BatchError::Invalid(
            "batch consists entirely of blank lines",
        ));
    }
    Ok(batch)
}

/// Per-receiver context describing what capabilities to honor when
/// formatting a multiline relay. Distilled out of handle_privmsg's
/// per-receiver cap checks so this module can build the wire frames
/// without needing the full SharedState.
pub struct ReceiverCaps<'a> {
    /// Receiver negotiated `message-tags` — without this they get a
    /// plain `:host PRIVMSG target :body` shape with no tags at all.
    pub has_tags: bool,
    /// Receiver negotiated `server-time` — `time=<iso>` tag goes on
    /// the BATCH opener (capable) or the first PRIVMSG (fallback).
    pub has_time: bool,
    /// Receiver negotiated `draft/multiline` — emit BATCH frames.
    /// Otherwise: emit N individual PRIVMSGs, msgid on first only.
    pub has_multiline: bool,
    /// Receiver opted into `account-tag`. When true and `sender_did`
    /// is set, `account=<did>` is injected into the carrier frame
    /// (BATCH opener or first PRIVMSG).
    pub wants_account: bool,
    /// Sender's DID, for the `account` tag injection.
    pub sender_did: Option<&'a str>,
}

/// Fixed message context for a single outbound multiline relay.
/// Shared across all receivers — only the per-receiver tag injection
/// and wire-shape decision vary.
pub struct RelayContext<'a> {
    pub hostmask: &'a str,
    pub command: &'a str,
    pub target: &'a str,
    /// `msgid` of the assembled logical message. Server-assigned at
    /// dispatch time; same value goes to every receiver, just placed
    /// differently per capability.
    pub msgid: &'a str,
    /// Time tag value (ISO 8601), already formatted. Only emitted to
    /// receivers that negotiated `server-time`.
    pub time_tag: &'a str,
    /// Client-only tags from the BATCH opener (commit-reveal event,
    /// signature, payload, etc.). Per spec, these belong on the BATCH
    /// opener for multiline-capable receivers and on the first
    /// PRIVMSG for fallback receivers.
    pub opener_tags: &'a HashMap<String, String>,
    /// Server-assigned batch id for outbound relay. Connection-scoped
    /// (each receiver sees its own namespace); we use the same value
    /// for every receiver for symmetry with logging.
    pub batch_id: &'a str,
    /// The original chunked body of the message, in arrival order.
    pub lines: &'a [BatchLine],
}

/// Build the sequence of wire frames a single receiver should see for
/// a multiline relay. Returns the frames in the order they should be
/// sent.
///
/// Multiline-capable receiver gets, in order:
///   1. `[@tags] BATCH +<id> draft/multiline <target>` (opener with
///      msgid + opener_tags + optional account + optional time)
///   2. For each line: `[@batch=<id>;maybe-concat] PRIVMSG <target> :<body>`
///   3. `BATCH -<id>` (closer)
///
/// Fallback receiver gets N individual frames:
///   1. `[@tags] PRIVMSG <target> :<line[0].body>` (msgid + opener_tags
///      + optional account + optional time on the FIRST frame only,
///        per spec § "Message ids" + § "Fallback")
///   2. For each subsequent line: `PRIVMSG <target> :<line.body>` with
///      no msgid and no opener tags
///
/// When `has_tags` is false, the receiver doesn't speak message-tags
/// at all → emit only plain `:hostmask PRIVMSG target :body` lines (no
/// BATCH frames, no msgid, no anything). Same shape as fallback but
/// without the tag prefix on the first PRIVMSG either.
pub fn build_outbound_multiline_frames(
    ctx: &RelayContext<'_>,
    caps: &ReceiverCaps<'_>,
) -> Vec<String> {
    if !caps.has_tags {
        return build_plain_fallback_frames(ctx);
    }
    if caps.has_multiline {
        build_capable_frames(ctx, caps)
    } else {
        build_tagged_fallback_frames(ctx, caps)
    }
}

fn build_plain_fallback_frames(ctx: &RelayContext<'_>) -> Vec<String> {
    // No message-tags negotiated — just bare PRIVMSG lines.
    ctx.lines
        .iter()
        .map(|line| {
            format!(
                ":{host} {cmd} {target} :{body}\r\n",
                host = ctx.hostmask,
                cmd = ctx.command,
                target = ctx.target,
                body = line.body,
            )
        })
        .collect()
}

fn build_capable_frames(ctx: &RelayContext<'_>, caps: &ReceiverCaps<'_>) -> Vec<String> {
    // Build opener tags: msgid + opener_tags + optional account + time.
    let mut opener = ctx.opener_tags.clone();
    opener.insert("msgid".to_string(), ctx.msgid.to_string());
    if caps.has_time {
        opener.insert("time".to_string(), ctx.time_tag.to_string());
    }
    if caps.wants_account
        && let Some(did) = caps.sender_did
    {
        opener.insert("account".to_string(), did.to_string());
    }

    let mut frames = Vec::with_capacity(ctx.lines.len() + 2);
    // BATCH opener.
    let opener_msg = crate::irc::Message {
        tags: opener,
        prefix: Some(ctx.hostmask.to_string()),
        command: "BATCH".to_string(),
        params: vec![
            format!("+{}", ctx.batch_id),
            "draft/multiline".to_string(),
            ctx.target.to_string(),
        ],
    };
    frames.push(format!("{opener_msg}\r\n"));

    // Per-line PRIVMSG (or NOTICE) frames, each carrying batch=<id>
    // and optionally draft/multiline-concat.
    for line in ctx.lines {
        let mut line_tags = HashMap::new();
        line_tags.insert("batch".to_string(), ctx.batch_id.to_string());
        if line.concat_to_previous {
            line_tags.insert("draft/multiline-concat".to_string(), String::new());
        }
        let line_msg = crate::irc::Message {
            tags: line_tags,
            prefix: Some(ctx.hostmask.to_string()),
            command: ctx.command.to_string(),
            params: vec![ctx.target.to_string(), line.body.clone()],
        };
        frames.push(format!("{line_msg}\r\n"));
    }

    // BATCH closer — no prefix, no tags, just `BATCH -<id>`.
    frames.push(format!("BATCH -{}\r\n", ctx.batch_id));
    frames
}

fn build_tagged_fallback_frames(ctx: &RelayContext<'_>, caps: &ReceiverCaps<'_>) -> Vec<String> {
    // Fallback receiver speaks message-tags but not multiline.
    // Per spec § "Fallback": deliver the constituent PRIVMSGs without
    // BATCH wrapping, with msgid + all client-only tags on the FIRST
    // line only.
    let mut frames = Vec::with_capacity(ctx.lines.len());
    for (i, line) in ctx.lines.iter().enumerate() {
        let tags = if i == 0 {
            let mut t = ctx.opener_tags.clone();
            t.insert("msgid".to_string(), ctx.msgid.to_string());
            if caps.has_time {
                t.insert("time".to_string(), ctx.time_tag.to_string());
            }
            if caps.wants_account
                && let Some(did) = caps.sender_did
            {
                t.insert("account".to_string(), did.to_string());
            }
            t
        } else {
            HashMap::new()
        };
        let msg = crate::irc::Message {
            tags,
            prefix: Some(ctx.hostmask.to_string()),
            command: ctx.command.to_string(),
            params: vec![ctx.target.to_string(), line.body.clone()],
        };
        frames.push(format!("{msg}\r\n"));
    }
    frames
}

/// Concatenate the lines of a closed `draft/multiline` batch into a
/// single body, per the spec's join rules:
///
/// > The combined message value of a multiline batch is defined as
/// > the concatenation of the messages from each individual line
/// > within the batch. Line messages are joined by a single line
/// > feed (\n) byte unless the draft/multiline-concat message tag is
/// > sent, in which case that line's message is directly joined with
/// > the previous line's message with no separation.
///
/// — <https://ircv3.net/specs/extensions/multiline> § Batch types
pub fn assemble_body(batch: &OpenBatch) -> String {
    let mut out = String::with_capacity(batch.byte_count);
    for (i, line) in batch.lines.iter().enumerate() {
        if i > 0 && !line.concat_to_previous {
            out.push('\n');
        }
        out.push_str(&line.body);
    }
    out
}

/// Count the open batches a session currently holds, given an already-locked
/// `open_batches` map. Single source of truth for the per-session concurrency
/// cap, shared by `handle_batch_open` (enforcement) and the connection-loop
/// rate-limit exemption pre-check so the two can't drift.
pub(super) fn count_session_open_batches(
    open: &HashMap<(String, String), OpenBatch>,
    session_id: &str,
) -> usize {
    open.keys().filter(|(sid, _)| sid == session_id).count()
}

/// Snapshot the number of open batches for a session — used by tests.
#[cfg(test)]
fn count_open_batches(state: &Arc<SharedState>, session_id: &str) -> usize {
    count_session_open_batches(&state.open_batches.lock(), session_id)
}

/// Top-level entry point for the inbound `BATCH` command. Parses the
/// reference-tag, dispatches to `handle_batch_open` (`+`) or
/// `handle_batch_close` (`-`), and emits a `FAIL BATCH <code>` reply
/// on validation errors.
///
/// On successful close of a `draft/multiline` batch, assembles the
/// accumulated lines per the spec's concat rules and re-feeds the
/// result through the normal `handle_privmsg` path — so the rest of
/// the server (history, broadcast, signing, commit-reveal verification,
/// etc.) sees one logical PRIVMSG/NOTICE regardless of how the sender
/// chunked it on the wire.
pub fn handle_batch_command(
    conn: &super::Connection,
    msg: &crate::irc::Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let reference = match msg.params.first() {
        Some(r) if !r.is_empty() => r,
        _ => {
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_INVALID,
                &[],
                "BATCH reference-tag required",
            );
            return;
        }
    };

    let (sign, batch_id) = reference.split_at(1);
    match sign {
        "+" => {
            // BATCH +<id> <type> [<params>...]
            let batch_type = msg.params.get(1).map(String::as_str).unwrap_or("");
            // For `draft/multiline` the third parameter is the target.
            let target = msg.params.get(2).map(String::as_str).unwrap_or("");

            // Per spec: client-only tags (`+`-prefixed) on the opener
            // carry the assembled message's metadata. Strip the `batch`
            // tag itself (won't be on an opener anyway) and store the rest.
            let opener_tags: HashMap<String, String> = msg
                .tags
                .iter()
                .filter(|(k, _)| k.as_str() != "batch")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if let Err(err) =
                handle_batch_open(state, session_id, batch_id, batch_type, target, opener_tags)
            {
                send_batch_error(state, server_name, session_id, send, &err);
            }
        }
        "-" => {
            // BATCH -<id>
            match handle_batch_close(state, session_id, batch_id) {
                Ok(closed_batch) => {
                    dispatch_assembled_batch(conn, &closed_batch, state);
                }
                Err(err) => {
                    send_batch_error(state, server_name, session_id, send, &err);
                }
            }
        }
        _ => {
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_INVALID,
                &[],
                "BATCH reference-tag must start with + or -",
            );
        }
    }
}

/// Emit a `FAIL BATCH <code> [<args>] :<reason>` reply for a
/// `BatchError`, picking the correct spec code + arguments.
pub fn send_batch_error(
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
    err: &BatchError,
) {
    match err {
        BatchError::MaxBytes => {
            let limit = MAX_BYTES.to_string();
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_MAX_BYTES,
                &[&limit],
                "Multiline batch byte limit exceeded",
            );
        }
        BatchError::MaxLines => {
            let limit = MAX_LINES.to_string();
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_MAX_LINES,
                &[&limit],
                "Multiline batch line limit exceeded",
            );
        }
        BatchError::InvalidTarget {
            batch_target,
            line_target,
        } => {
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_INVALID_TARGET,
                &[batch_target.as_str(), line_target.as_str()],
                "Invalid multiline target",
            );
        }
        BatchError::Invalid(reason) => {
            send_fail(
                state,
                server_name,
                session_id,
                send,
                fail_code::MULTILINE_INVALID,
                &[],
                reason,
            );
        }
    }
}

fn send_fail(
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
    code: &str,
    extra_args: &[&str],
    human_reason: &str,
) {
    // Standard-replies frame: `FAIL <command> <code> [<args>...] :<reason>`.
    let mut params: Vec<&str> = vec!["BATCH", code];
    params.extend_from_slice(extra_args);
    params.push(human_reason);
    let reply = crate::irc::Message::from_server(server_name, "FAIL", params);
    send(state, session_id, format!("{reply}\r\n"));
}

/// Take a closed batch and re-dispatch it as a single logical
/// PRIVMSG/NOTICE. The body is assembled per concat rules; the
/// client-only tags from the BATCH opener carry through; the
/// command (PRIVMSG vs NOTICE) is whatever the first line inside the
/// batch used. The downstream `handle_privmsg` does its normal thing
/// — flood protection, history persistence, signing, broadcast — so
/// the rest of the server treats the assembled message identically
/// to a single-PRIVMSG send.
fn dispatch_assembled_batch(conn: &super::Connection, batch: &OpenBatch, state: &Arc<SharedState>) {
    // first_command is set on first append (try_route_to_batch). A
    // batch with zero lines wouldn't have one, but the close-time
    // entirely-blank-batch guard rejects that case before we get
    // here, so first_command is always Some when we reach dispatch.
    let command = batch.first_command.as_deref().unwrap_or("PRIVMSG");
    let body = assemble_body(batch);
    super::messaging::handle_privmsg_with_multiline(
        conn,
        command,
        &batch.target,
        &body,
        &batch.opener_tags,
        state,
        Some(&batch.lines),
    );
}

// ──────────────────────────────────────────────────────────────────
// Unit tests for OpenBatch + cost accounting (pure logic, no state)
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_batch() -> OpenBatch {
        OpenBatch {
            batch_id: "abc".to_string(),
            batch_type: "draft/multiline".to_string(),
            target: "#c".to_string(),
            opener_tags: HashMap::new(),
            lines: Vec::new(),
            byte_count: 0,
            first_command: None,
        }
    }

    #[test]
    fn cost_of_first_line_is_just_the_body() {
        let b = empty_batch();
        assert_eq!(b.cost_of_appending("hello", false), 5);
        // The concat marker on the first line is invalid per spec, but
        // the cost helper doesn't validate — it just accounts. The
        // first-line concat case still doesn't add a separator byte
        // because there's nothing to join *to*.
        assert_eq!(b.cost_of_appending("hello", true), 5);
    }

    #[test]
    fn cost_of_subsequent_normal_line_adds_separator_byte() {
        let mut b = empty_batch();
        b.lines.push(BatchLine {
            body: "first".to_string(),
            concat_to_previous: false,
            command: "PRIVMSG".to_string(),
        });
        // "world" (5) + \n separator (1) = 6.
        assert_eq!(b.cost_of_appending("world", false), 6);
    }

    #[test]
    fn cost_of_subsequent_concat_line_does_not_add_separator() {
        let mut b = empty_batch();
        b.lines.push(BatchLine {
            body: "first".to_string(),
            concat_to_previous: false,
            command: "PRIVMSG".to_string(),
        });
        // Concat means no separator → cost is just body length.
        assert_eq!(b.cost_of_appending("ABC", true), 3);
    }

    #[test]
    fn max_bytes_constant_matches_spec_example() {
        // The spec uses 40000 in its own example; keeping policy
        // aligned makes interop with the example clients painless.
        assert_eq!(MAX_BYTES, 40_000);
    }

    #[test]
    fn max_lines_constant_is_sane_default() {
        // 100 lines is enough for any structured LLM turn while
        // staying well below abusive territory.
        assert_eq!(MAX_LINES, 100);
    }

    #[test]
    fn max_concurrent_batches_per_session_is_sane_default() {
        // Clients in the wild open one at a time; 5 leaves headroom
        // without permitting unbounded per-session state.
        assert_eq!(MAX_CONCURRENT_BATCHES_PER_SESSION, 5);
    }

    // ──────────────────────────────────────────────────────────────
    // State machine tests (against a real SharedState)
    // ──────────────────────────────────────────────────────────────

    use crate::server::SharedState;
    use parking_lot::Mutex;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Minimal SharedState for these state-machine tests. Mirrors the
    /// `test_state()` helper in s2s_adversarial_tests but with only
    /// the fields the batch handlers actually touch initialised; the
    /// rest are placeholder defaults.
    fn test_state() -> Arc<SharedState> {
        let config = crate::config::ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            server_name: "test-multiline".to_string(),
            challenge_timeout_secs: 60,
            ..Default::default()
        };
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Arc::new(SharedState {
            server_name: config.server_name.clone(),
            challenge_store: crate::sasl::ChallengeStore::new(60),
            did_resolver: freeq_sdk::did::DidResolver::static_map(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(crate::server::NickMap::new()),
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
            db: None,
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
            metrics: crate::server::Metrics::default(),
        })
    }

    fn empty_tags() -> HashMap<String, String> {
        HashMap::new()
    }

    fn tag(key: &str, value: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(key.to_string(), value.to_string());
        m
    }

    // ── open / close lifecycle ────────────────────────────────────

    #[test]
    fn batch_open_creates_state() {
        let state = test_state();
        assert!(
            handle_batch_open(
                &state,
                "sess-A",
                "abc",
                "draft/multiline",
                "#cloudcity",
                empty_tags()
            )
            .is_ok()
        );
        assert_eq!(count_open_batches(&state, "sess-A"), 1);
    }

    #[test]
    fn batch_close_returns_and_removes_state() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        // Need at least one non-blank line for close to succeed.
        let routed = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "hi",
            false,
        );
        assert!(matches!(routed, RouteOutcome::Absorbed));

        let closed = handle_batch_close(&state, "sess-A", "abc").unwrap();
        assert_eq!(closed.lines.len(), 1);
        assert_eq!(closed.lines[0].body, "hi");
        assert_eq!(count_open_batches(&state, "sess-A"), 0);
    }

    #[test]
    fn batch_close_unknown_id_is_invalid() {
        let state = test_state();
        let err = handle_batch_close(&state, "sess-A", "nope").unwrap_err();
        assert!(matches!(err, BatchError::Invalid(_)));
    }

    #[test]
    fn duplicate_batch_open_rejected() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        let err = handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap_err();
        assert!(matches!(err, BatchError::Invalid(_)));
    }

    #[test]
    fn unknown_batch_type_rejected() {
        let state = test_state();
        let err = handle_batch_open(&state, "sess-A", "abc", "chathistory", "#c", empty_tags())
            .unwrap_err();
        assert!(matches!(err, BatchError::Invalid(_)));
    }

    #[test]
    fn max_concurrent_batches_per_session_enforced() {
        let state = test_state();
        for i in 0..MAX_CONCURRENT_BATCHES_PER_SESSION {
            handle_batch_open(
                &state,
                "sess-A",
                &format!("batch-{i}"),
                "draft/multiline",
                "#c",
                empty_tags(),
            )
            .unwrap();
        }
        let err = handle_batch_open(
            &state,
            "sess-A",
            "one-too-many",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap_err();
        assert!(matches!(err, BatchError::Invalid(_)));
    }

    #[test]
    fn batches_isolated_per_session() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        // Same batch id on a different session is fine — keys are
        // `(session_id, batch_id)`.
        handle_batch_open(
            &state,
            "sess-B",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        assert_eq!(count_open_batches(&state, "sess-A"), 1);
        assert_eq!(count_open_batches(&state, "sess-B"), 1);
    }

    // ── routing (PRIVMSG / NOTICE with batch tag) ──────────────────

    #[test]
    fn message_without_batch_tag_is_not_in_batch() {
        let state = test_state();
        let outcome = try_route_to_batch(
            &state,
            "sess-A",
            &empty_tags(),
            "PRIVMSG",
            "#c",
            "hi",
            false,
        );
        assert!(matches!(outcome, RouteOutcome::NotInBatch));
    }

    #[test]
    fn message_with_batch_tag_for_unknown_id_is_not_in_batch() {
        // Per spec, a `batch=<id>` pointing at no open batch is
        // treated as a normal standalone message.
        let state = test_state();
        let outcome = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "nope"),
            "PRIVMSG",
            "#c",
            "hi",
            false,
        );
        assert!(matches!(outcome, RouteOutcome::NotInBatch));
    }

    #[test]
    fn line_target_mismatch_is_invalid_target() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#cloudcity",
            empty_tags(),
        )
        .unwrap();
        let outcome = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#wrongchan",
            "hi",
            false,
        );
        match outcome {
            RouteOutcome::Error(BatchError::InvalidTarget {
                batch_target,
                line_target,
            }) => {
                assert_eq!(batch_target, "#cloudcity");
                assert_eq!(line_target, "#wrongchan");
            }
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[test]
    fn mixing_privmsg_and_notice_in_one_batch_is_invalid() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "first",
            false,
        );
        let outcome = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "NOTICE",
            "#c",
            "uh oh",
            false,
        );
        assert!(matches!(
            outcome,
            RouteOutcome::Error(BatchError::Invalid(_))
        ));
    }

    #[test]
    fn first_line_with_concat_tag_is_invalid() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        let mut tags = tag("batch", "abc");
        tags.insert("draft/multiline-concat".to_string(), String::new());
        let outcome = try_route_to_batch(&state, "sess-A", &tags, "PRIVMSG", "#c", "hello", true);
        assert!(matches!(
            outcome,
            RouteOutcome::Error(BatchError::Invalid(_))
        ));
    }

    #[test]
    fn blank_line_with_concat_tag_is_invalid() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        // First line: normal, non-blank.
        try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "hi",
            false,
        );
        // Second line: blank + concat — rejected.
        let outcome = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "",
            true,
        );
        assert!(matches!(
            outcome,
            RouteOutcome::Error(BatchError::Invalid(_))
        ));
    }

    #[test]
    fn entirely_blank_batch_rejected_at_close() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        // Two blank lines, no concat (so each is "allowed" mid-batch).
        try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "",
            false,
        );
        try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "",
            false,
        );
        let err = handle_batch_close(&state, "sess-A", "abc").unwrap_err();
        assert!(matches!(err, BatchError::Invalid(_)));
    }

    #[test]
    fn byte_budget_enforced_at_append() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        // First line fills the budget exactly.
        let big = "x".repeat(MAX_BYTES);
        let r1 = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            &big,
            false,
        );
        assert!(matches!(r1, RouteOutcome::Absorbed));
        // Any non-concat second line adds the body + 1 separator
        // byte, so even a 0-byte line should push us over.
        let r2 = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "",
            false,
        );
        assert!(matches!(r2, RouteOutcome::Error(BatchError::MaxBytes)));
    }

    // ── assemble_body (concat rules) ──────────────────────────────

    fn line(body: &str, concat: bool) -> BatchLine {
        BatchLine {
            body: body.to_string(),
            concat_to_previous: concat,
            command: "PRIVMSG".to_string(),
        }
    }

    fn batch_with_lines(lines: Vec<BatchLine>) -> OpenBatch {
        OpenBatch {
            batch_id: "x".to_string(),
            batch_type: "draft/multiline".to_string(),
            target: "#c".to_string(),
            opener_tags: HashMap::new(),
            lines,
            byte_count: 0,
            first_command: Some("PRIVMSG".to_string()),
        }
    }

    #[test]
    fn assemble_single_line_yields_just_that_line() {
        let b = batch_with_lines(vec![line("only", false)]);
        assert_eq!(assemble_body(&b), "only");
    }

    #[test]
    fn assemble_joins_normal_lines_with_newline() {
        let b = batch_with_lines(vec![
            line("first", false),
            line("second", false),
            line("third", false),
        ]);
        assert_eq!(assemble_body(&b), "first\nsecond\nthird");
    }

    #[test]
    fn assemble_concat_line_joins_without_separator() {
        // Splitting one long word across two chunks should rejoin
        // seamlessly — this is the spec's "splitting long lines" case.
        let b = batch_with_lines(vec![
            line("hello ", false),
            line("everyone", true), // concat-to-previous
        ]);
        assert_eq!(assemble_body(&b), "hello everyone");
    }

    #[test]
    fn assemble_mixed_concat_and_newline_lines() {
        // The spec's own example:
        //   hello
        //
        //   how is everyone?
        // sent as: "hello", "", "how is ", concat:"everyone?"
        let b = batch_with_lines(vec![
            line("hello", false),
            line("", false),
            line("how is ", false),
            line("everyone?", true),
        ]);
        assert_eq!(assemble_body(&b), "hello\n\nhow is everyone?");
    }

    #[test]
    fn assemble_appends_no_trailing_newline() {
        // Spec: "No line feed is appended to the final line message
        // of a batch." Belt-and-suspenders test.
        let b = batch_with_lines(vec![line("first", false), line("second", false)]);
        let assembled = assemble_body(&b);
        assert!(
            !assembled.ends_with('\n'),
            "trailing newline leaked: {assembled:?}"
        );
    }

    // ── outbound wire formatting ──────────────────────────────────

    fn test_lines() -> Vec<BatchLine> {
        vec![
            line("first", false),
            line("second", false),
            line("third", true), // concat-to-previous
        ]
    }

    fn test_ctx<'a>(
        lines: &'a [BatchLine],
        opener_tags: &'a HashMap<String, String>,
    ) -> RelayContext<'a> {
        RelayContext {
            hostmask: "nick!u@host",
            command: "PRIVMSG",
            target: "#cloudcity",
            msgid: "01J_MSGID",
            time_tag: "2026-05-27T18:00:00.000Z",
            opener_tags,
            batch_id: "ml42",
            lines,
        }
    }

    fn caps_capable() -> ReceiverCaps<'static> {
        ReceiverCaps {
            has_tags: true,
            has_time: false,
            has_multiline: true,
            wants_account: false,
            sender_did: None,
        }
    }

    fn caps_fallback_tagged() -> ReceiverCaps<'static> {
        ReceiverCaps {
            has_tags: true,
            has_time: false,
            has_multiline: false,
            wants_account: false,
            sender_did: None,
        }
    }

    fn caps_plain() -> ReceiverCaps<'static> {
        ReceiverCaps {
            has_tags: false,
            has_time: false,
            has_multiline: false,
            wants_account: false,
            sender_did: None,
        }
    }

    #[test]
    fn capable_receiver_gets_batch_wrapped_frames() {
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let frames =
            build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps_capable());
        // Opener + 3 PRIVMSGs + closer = 5 frames.
        assert_eq!(frames.len(), 5);
        // Opener: BATCH + + draft/multiline + target, with msgid tag.
        assert!(frames[0].contains("BATCH +ml42"));
        assert!(frames[0].contains("draft/multiline"));
        assert!(frames[0].contains("#cloudcity"));
        assert!(frames[0].contains("msgid=01J_MSGID"));
        // Per-line frames carry batch=<id>.
        assert!(frames[1].contains("batch=ml42"));
        assert!(frames[1].contains("PRIVMSG #cloudcity"));
        assert!(frames[1].contains("first"));
        assert!(frames[2].contains("batch=ml42"));
        assert!(frames[2].contains("second"));
        // Third line: concat tag flows through.
        assert!(frames[3].contains("batch=ml42"));
        assert!(frames[3].contains("draft/multiline-concat"));
        // Closer: BATCH - with no tags or prefix.
        assert_eq!(frames[4], "BATCH -ml42\r\n");
    }

    #[test]
    fn capable_receiver_msgid_only_on_opener_not_on_chunks() {
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let frames =
            build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps_capable());
        assert!(frames[0].contains("msgid=01J_MSGID"));
        // Subsequent PRIVMSG frames must not carry msgid (per spec).
        for (i, frame) in frames.iter().enumerate().skip(1).take(3) {
            assert!(
                !frame.contains("msgid"),
                "frame {i} unexpectedly carries msgid: {frame}"
            );
        }
    }

    #[test]
    fn capable_receiver_opener_carries_client_only_tags() {
        let lines = test_lines();
        let mut opener_tags = HashMap::new();
        opener_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
        opener_tags.insert(
            "+freeq.at/payload".to_string(),
            r#"{"reveal_of":"01J_COMMIT","salt":"abc"}"#.to_string(),
        );
        let frames =
            build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps_capable());
        assert!(
            frames[0].contains("+freeq.at/event=reveal"),
            "opener missing event tag: {}",
            frames[0]
        );
        // Subsequent frames must NOT carry the client-only tags.
        for frame in frames.iter().skip(1).take(3) {
            assert!(
                !frame.contains("+freeq.at/event"),
                "client-only tag leaked into chunk: {frame}"
            );
        }
    }

    #[test]
    fn capable_receiver_with_account_tag_adds_account() {
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let mut caps = caps_capable();
        caps.wants_account = true;
        caps.sender_did = Some("did:key:zSENDER");
        let frames = build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps);
        // Account on the opener only.
        assert!(frames[0].contains("account=did:key:zSENDER"));
        for frame in frames.iter().skip(1).take(3) {
            assert!(!frame.contains("account="));
        }
    }

    #[test]
    fn fallback_tagged_receiver_gets_n_privmsgs_msgid_on_first() {
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let frames = build_outbound_multiline_frames(
            &test_ctx(&lines, &opener_tags),
            &caps_fallback_tagged(),
        );
        // No BATCH frames; one PRIVMSG per chunk.
        assert_eq!(frames.len(), 3);
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
        assert!(frames[0].contains("msgid=01J_MSGID"));
        assert!(!frames[1].contains("msgid"));
        assert!(!frames[2].contains("msgid"));
    }

    #[test]
    fn fallback_tagged_receiver_client_only_tags_on_first_only() {
        let lines = test_lines();
        let mut opener_tags = HashMap::new();
        opener_tags.insert("+freeq.at/event".to_string(), "reveal".to_string());
        let frames = build_outbound_multiline_frames(
            &test_ctx(&lines, &opener_tags),
            &caps_fallback_tagged(),
        );
        assert!(frames[0].contains("+freeq.at/event=reveal"));
        assert!(!frames[1].contains("+freeq.at/event"));
        assert!(!frames[2].contains("+freeq.at/event"));
    }

    #[test]
    fn plain_receiver_gets_n_bare_privmsgs() {
        // No message-tags negotiated → no tags at all anywhere.
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let frames =
            build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps_plain());
        assert_eq!(frames.len(), 3);
        for frame in &frames {
            // Bare format: `:host PRIVMSG #c :body`. No `@` tag prefix.
            assert!(
                !frame.starts_with('@'),
                "plain receiver got tagged frame: {frame}"
            );
            assert!(frame.starts_with(":nick!u@host PRIVMSG #cloudcity :"));
            assert!(!frame.contains("BATCH"));
        }
        assert!(frames[0].ends_with(":first\r\n"));
        assert!(frames[1].ends_with(":second\r\n"));
        assert!(frames[2].ends_with(":third\r\n"));
    }

    #[test]
    fn capable_receiver_with_server_time_adds_time_tag_to_opener_only() {
        let lines = test_lines();
        let opener_tags = HashMap::new();
        let mut caps = caps_capable();
        caps.has_time = true;
        let frames = build_outbound_multiline_frames(&test_ctx(&lines, &opener_tags), &caps);
        assert!(frames[0].contains("time=2026-05-27T18:00:00.000Z"));
        for frame in frames.iter().skip(1).take(3) {
            assert!(!frame.contains("time="));
        }
    }

    #[test]
    fn line_budget_enforced_at_append() {
        let state = test_state();
        handle_batch_open(
            &state,
            "sess-A",
            "abc",
            "draft/multiline",
            "#c",
            empty_tags(),
        )
        .unwrap();
        for _ in 0..MAX_LINES {
            let r = try_route_to_batch(
                &state,
                "sess-A",
                &tag("batch", "abc"),
                "PRIVMSG",
                "#c",
                "ok",
                false,
            );
            assert!(matches!(r, RouteOutcome::Absorbed));
        }
        let r_over = try_route_to_batch(
            &state,
            "sess-A",
            &tag("batch", "abc"),
            "PRIVMSG",
            "#c",
            "ok",
            false,
        );
        assert!(matches!(r_over, RouteOutcome::Error(BatchError::MaxLines)));
    }
}
