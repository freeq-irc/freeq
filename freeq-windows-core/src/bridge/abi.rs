//! C ABI exports — the public surface consumed by C# P/Invoke.
//!
//! All functions are `extern "C"` and `#[no_mangle]`.
//! Handles are opaque `u64` IDs into a global `DashMap`.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::bridge::callback::{CallbackSink, EventCallback};
use crate::bridge::envelope::EventEnvelope;
use crate::core::AppCore;
use crate::error::FfiResult;
use crate::event::convert_event;
use crate::RUNTIME;

/// Global handle table. Maps handle IDs → Arc<AppCore>.
static HANDLES: Lazy<DashMap<u64, Arc<AppCore>>> = Lazy::new(DashMap::new);

/// Monotonic handle counter.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Helper: read a C string pointer into a Rust String, returning None on null or invalid UTF-8.
unsafe fn read_c_str(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(String::from)
}

// ─── Create / Destroy ────────────────────────────────────────────────

/// Create a new client instance from a JSON configuration string.
///
/// # Safety
///
/// `config_json` must be a valid, NUL-terminated UTF-8 C string, or null.
///
/// Config JSON schema:
/// ```json
/// {
///   "server": "irc.example.com:6697",
///   "nick": "myuser",
///   "tls": true
/// }
/// ```
///
/// Returns a non-zero handle on success, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_create_client(config_json: *const c_char) -> u64 {
    let Some(json_str) = (unsafe { read_c_str(config_json) }) else {
        tracing::error!("freeq_win_create_client: null or invalid config_json");
        return 0;
    };

    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("freeq_win_create_client: invalid JSON: {e}");
            return 0;
        }
    };

    let server = parsed["server"]
        .as_str()
        .unwrap_or("127.0.0.1:6667")
        .to_string();
    let nick = parsed["nick"].as_str().unwrap_or("freeq_user").to_string();
    let tls = parsed["tls"].as_bool().unwrap_or(false);

    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let core = Arc::new(AppCore {
        id,
        sdk_handle: Mutex::new(None),
        connected: AtomicBool::new(false),
        nick: Mutex::new(nick.clone()),
        callback: Mutex::new(None),
        server_addr: server,
        initial_nick: nick,
        tls,
        web_token: Mutex::new(None),
        channels: Mutex::new(Vec::new()),
    });

    HANDLES.insert(id, core);
    tracing::debug!("freeq_win_create_client: created handle {id}");
    id
}

/// Destroy a client instance and free all associated resources.
///
/// Safe to call multiple times — second call is a no-op.
///
/// # Safety
///
/// `handle` must be a value previously returned by `freeq_win_create_client`,
/// or the call is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_destroy_client(handle: u64) {
    if let Some((_, core)) = HANDLES.remove(&handle) {
        tracing::debug!("freeq_win_destroy_client: destroying handle {handle}");
        // Disconnect if still connected
        let sdk = core.sdk_handle.lock().take();
        if let Some(h) = sdk {
            RUNTIME.spawn(async move {
                let _ = h.quit(Some("Client destroyed")).await;
            });
        }
        core.connected.store(false, Ordering::Release);
    }
}

// ─── Subscribe ───────────────────────────────────────────────────────

/// Register the event callback for a client.
///
/// The callback will be invoked from a background thread with JSON event envelopes.
/// Only one callback can be registered per client; subsequent calls replace the previous one.
///
/// # Safety
///
/// `cb` must be a valid function pointer. `user_data` must remain valid for the
/// lifetime of the subscription (until destroy or a replacement subscribe call).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_subscribe_events(
    handle: u64,
    cb: EventCallback,
    user_data: *mut c_void,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    *core.callback.lock() = Some(CallbackSink::new(cb, user_data));
    tracing::debug!("freeq_win_subscribe_events: callback registered for handle {handle}");
    FfiResult::Ok as i32
}

// ─── Auth ────────────────────────────────────────────────────────────

/// Set the web token for SASL authentication before connecting.
///
/// # Safety
///
/// `token` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_set_web_token(handle: u64, token: *const c_char) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(token_str) = (unsafe { read_c_str(token) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    *core.web_token.lock() = Some(token_str);
    FfiResult::Ok as i32
}

// ─── Connect / Disconnect ────────────────────────────────────────────

/// Connect to the IRC server.
///
/// Spawns a background thread that enters the tokio runtime, establishes the
/// connection, and pumps events to the registered callback.
/// Returns immediately — connection happens asynchronously.
///
/// # Safety
///
/// `handle` must be a valid handle from `freeq_win_create_client`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_connect(handle: u64) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let core = Arc::clone(&core);

    std::thread::spawn(move || {
        RUNTIME.block_on(async move {
            let nick = core.nick.lock().clone();
            let web_token = core.web_token.lock().take();

            let config = freeq_sdk::client::ConnectConfig {
                server_addr: core.server_addr.clone(),
                nick: nick.clone(),
                user: nick.clone(),
                realname: "freeq windows".to_string(),
                tls: core.tls,
                tls_insecure: false,
                web_token,
                websocket_url: None,
                ..Default::default()
            };

            let (client_handle, mut event_rx) = freeq_sdk::client::connect(config, None);

            *core.sdk_handle.lock() = Some(client_handle);
            core.connected.store(true, Ordering::Release);

            let mut seq: u64 = 0;

            while let Some(event) = event_rx.recv().await {
                let domain_event = convert_event(&event);

                // Track connection state
                if matches!(
                    &domain_event,
                    crate::event::DomainEvent::Disconnected { .. }
                ) {
                    core.connected.store(false, Ordering::Release);
                }

                // Track nick changes
                if let crate::event::DomainEvent::Registered { ref nick } = &domain_event {
                    *core.nick.lock() = nick.clone();
                }

                // Track joined channels (for reconnect)
                match &domain_event {
                    crate::event::DomainEvent::Joined {
                        channel,
                        nick: join_nick,
                    } if join_nick.eq_ignore_ascii_case(&core.nick.lock()) => {
                        let mut chans = core.channels.lock();
                        if !chans.iter().any(|c| c.eq_ignore_ascii_case(channel)) {
                            chans.push(channel.clone());
                        }
                    }
                    crate::event::DomainEvent::Parted {
                        channel,
                        nick: part_nick,
                    } if part_nick.eq_ignore_ascii_case(&core.nick.lock()) => {
                        core.channels
                            .lock()
                            .retain(|c| !c.eq_ignore_ascii_case(channel));
                    }
                    crate::event::DomainEvent::Kicked {
                        channel,
                        nick: kick_nick,
                        ..
                    } if kick_nick.eq_ignore_ascii_case(&core.nick.lock()) => {
                        core.channels
                            .lock()
                            .retain(|c| !c.eq_ignore_ascii_case(channel));
                    }
                    _ => {}
                }

                // Dispatch via callback
                if let Some(ref cb) = *core.callback.lock() {
                    seq += 1;
                    let envelope = EventEnvelope::new(seq, domain_event);
                    if let Ok(json) = serde_json::to_string(&envelope) {
                        cb.dispatch(&json);
                    }
                }
            }

            // Event loop ended — connection is gone
            core.connected.store(false, Ordering::Release);
        });
    });

    FfiResult::Ok as i32
}

/// Disconnect from the IRC server.
///
/// # Safety
///
/// `handle` must be a valid handle from `freeq_win_create_client`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_disconnect(handle: u64) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let sdk = core.sdk_handle.lock().take();
    match sdk {
        Some(h) => {
            RUNTIME.spawn(async move {
                let _ = h.quit(Some("Goodbye")).await;
            });
            core.connected.store(false, Ordering::Release);
            FfiResult::Ok as i32
        }
        None => FfiResult::NotConnected as i32,
    }
}

// ─── IRC Operations ──────────────────────────────────────────────────

/// Join an IRC channel.
///
/// # Safety
///
/// `channel` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_join(handle: u64, channel: *const c_char) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(chan) = (unsafe { read_c_str(channel) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.join(&chan).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send a PRIVMSG to a target (channel or nick).
///
/// # Safety
///
/// `target` and `text` must each be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_send_message(
    handle: u64,
    target: *const c_char,
    text: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(txt) = (unsafe { read_c_str(text) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.privmsg(&tgt, &txt).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send a raw IRC line.
///
/// # Safety
///
/// `line` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_send_raw(handle: u64, line: *const c_char) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(raw) = (unsafe { read_c_str(line) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.raw(&raw).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

// ─── Rich messaging ─────────────────────────────────────────────────

/// Reply to a message (sends PRIVMSG with +draft/reply tag).
///
/// # Safety
///
/// `target`, `msgid`, and `text` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_reply(
    handle: u64,
    target: *const c_char,
    msgid: *const c_char,
    text: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(txt) = (unsafe { read_c_str(text) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.reply(&tgt, &mid, &txt).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Edit a previously sent message.
///
/// # Safety
///
/// `target`, `msgid`, and `text` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_edit_message(
    handle: u64,
    target: *const c_char,
    msgid: *const c_char,
    text: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(txt) = (unsafe { read_c_str(text) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.edit_message(&tgt, &mid, &txt).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Delete a message.
///
/// # Safety
///
/// `target` and `msgid` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_delete_message(
    handle: u64,
    target: *const c_char,
    msgid: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.delete_message(&tgt, &mid).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Add a reaction to a message.
///
/// # Safety
///
/// `target`, `emoji`, and `msgid` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_react(
    handle: u64,
    target: *const c_char,
    emoji: *const c_char,
    msgid: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(emo) = (unsafe { read_c_str(emoji) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.react(&tgt, &emo, &mid).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send typing indicator start.
///
/// # Safety
///
/// `target` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_typing_start(handle: u64, target: *const c_char) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.typing_start(&tgt).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send typing indicator stop.
///
/// # Safety
///
/// `target` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_typing_stop(handle: u64, target: *const c_char) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.typing_stop(&tgt).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Request latest N messages of history (CHATHISTORY LATEST).
///
/// # Safety
///
/// `target` must be a valid, NUL-terminated UTF-8 C string, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_history_latest(
    handle: u64,
    target: *const c_char,
    count: u32,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.history_latest(&tgt, count as usize).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Request N messages before a given msgid (CHATHISTORY BEFORE).
///
/// # Safety
///
/// `target` and `msgid` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_history_before(
    handle: u64,
    target: *const c_char,
    msgid: *const c_char,
    count: u32,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.history_before(&tgt, &mid, count as usize).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Pin a message in a channel.
///
/// # Safety
///
/// `channel` and `msgid` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_pin(
    handle: u64,
    channel: *const c_char,
    msgid: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(chan) = (unsafe { read_c_str(channel) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.pin(&chan, &mid).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Unpin a message in a channel.
///
/// # Safety
///
/// `channel` and `msgid` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_unpin(
    handle: u64,
    channel: *const c_char,
    msgid: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(chan) = (unsafe { read_c_str(channel) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(mid) = (unsafe { read_c_str(msgid) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.unpin(&chan, &mid).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send a PRIVMSG with custom tags (tags_json is a JSON object string).
///
/// # Safety
///
/// `target`, `text`, and `tags_json` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_send_tagged(
    handle: u64,
    target: *const c_char,
    text: *const c_char,
    tags_json: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(txt) = (unsafe { read_c_str(text) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(tags_str) = (unsafe { read_c_str(tags_json) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let tags: std::collections::HashMap<String, String> = match serde_json::from_str(&tags_str) {
        Ok(t) => t,
        Err(_) => return FfiResult::InvalidArgument as i32,
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.send_tagged(&tgt, &txt, tags).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Send a TAGMSG with custom tags (tags_json is a JSON object string).
///
/// # Safety
///
/// `target` and `tags_json` must be valid, NUL-terminated UTF-8 C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_send_tagmsg(
    handle: u64,
    target: *const c_char,
    tags_json: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(tgt) = (unsafe { read_c_str(target) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(tags_str) = (unsafe { read_c_str(tags_json) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let tags: std::collections::HashMap<String, String> = match serde_json::from_str(&tags_str) {
        Ok(t) => t,
        Err(_) => return FfiResult::InvalidArgument as i32,
    };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.send_tagmsg(&tgt, tags).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

/// Set a channel mode.
///
/// # Safety
///
/// `channel`, `flags`, and `arg` must be valid, NUL-terminated UTF-8 C strings, or null.
/// `arg` may be null for modes that don't require an argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_mode(
    handle: u64,
    channel: *const c_char,
    flags: *const c_char,
    arg: *const c_char,
) -> i32 {
    let Some(core) = HANDLES.get(&handle) else {
        return FfiResult::InvalidHandle as i32;
    };
    let Some(chan) = (unsafe { read_c_str(channel) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let Some(flg) = (unsafe { read_c_str(flags) }) else {
        return FfiResult::InvalidArgument as i32;
    };
    let mode_arg = unsafe { read_c_str(arg) };
    let sdk = core.sdk_handle.lock().clone();
    let Some(h) = sdk else {
        return FfiResult::NotConnected as i32;
    };

    let (tx, rx) = std::sync::mpsc::channel();
    RUNTIME.spawn(async move {
        let result = h.mode(&chan, &flg, mode_arg.as_deref()).await;
        let _ = tx.send(result);
    });

    match rx.recv() {
        Ok(Ok(())) => FfiResult::Ok as i32,
        _ => FfiResult::Internal as i32,
    }
}

// ─── State Query ─────────────────────────────────────────────────────

/// Get a JSON snapshot of the client's current state.
///
/// Returns a heap-allocated C string that must be freed with `freeq_win_free_string`.
/// Returns null if the handle is invalid.
///
/// # Safety
///
/// `handle` must be a valid handle from `freeq_win_create_client`.
/// The returned pointer must be freed with `freeq_win_free_string`.
///
/// Snapshot schema:
/// ```json
/// {
///   "connected": true,
///   "nick": "myuser",
///   "server": "irc.example.com:6697"
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_get_snapshot_json(handle: u64) -> *mut c_char {
    let Some(core) = HANDLES.get(&handle) else {
        return std::ptr::null_mut();
    };

    let snapshot = serde_json::json!({
        "connected": core.connected.load(Ordering::Acquire),
        "nick": *core.nick.lock(),
        "server": core.server_addr,
    });

    match CString::new(snapshot.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string previously returned by `freeq_win_get_snapshot_json`.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `freeq_win_get_snapshot_json`.
/// Must not be called more than once for the same pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeq_win_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn make_config(json: &str) -> CString {
        CString::new(json).unwrap()
    }

    #[test]
    fn test_create_and_destroy() {
        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_ne!(handle, 0);
        assert!(HANDLES.contains_key(&handle));

        unsafe { freeq_win_destroy_client(handle) };
        assert!(!HANDLES.contains_key(&handle));
    }

    #[test]
    fn test_create_null_config() {
        let handle = unsafe { freeq_win_create_client(std::ptr::null()) };
        assert_eq!(handle, 0);
    }

    #[test]
    fn test_create_invalid_json() {
        let config = make_config("not json");
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_eq!(handle, 0);
    }

    #[test]
    fn test_double_destroy() {
        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_ne!(handle, 0);

        unsafe { freeq_win_destroy_client(handle) };
        // Second destroy is a no-op
        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_invalid_handle_returns_error() {
        let result = unsafe { freeq_win_join(999999, std::ptr::null()) };
        assert_eq!(result, FfiResult::InvalidHandle as i32);

        let result = unsafe { freeq_win_connect(999999) };
        assert_eq!(result, FfiResult::InvalidHandle as i32);

        let result = unsafe { freeq_win_disconnect(999999) };
        assert_eq!(result, FfiResult::InvalidHandle as i32);
    }

    #[test]
    fn test_subscribe_events() {
        unsafe extern "C" fn noop_cb(_ptr: *const c_char, _len: usize, _user_data: *mut c_void) {}

        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_ne!(handle, 0);

        let result = unsafe { freeq_win_subscribe_events(handle, noop_cb, std::ptr::null_mut()) };
        assert_eq!(result, FfiResult::Ok as i32);

        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_snapshot_json() {
        let config = make_config(r#"{"server":"localhost:6667","nick":"snapuser"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_ne!(handle, 0);

        let ptr = unsafe { freeq_win_get_snapshot_json(handle) };
        assert!(!ptr.is_null());

        let json_str = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["connected"], false);
        assert_eq!(parsed["nick"], "snapuser");
        assert_eq!(parsed["server"], "localhost:6667");

        unsafe { freeq_win_free_string(ptr) };
        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_snapshot_invalid_handle() {
        let ptr = unsafe { freeq_win_get_snapshot_json(999999) };
        assert!(ptr.is_null());
    }

    #[test]
    fn test_set_web_token() {
        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };

        let token = CString::new("my-auth-token").unwrap();
        let result = unsafe { freeq_win_set_web_token(handle, token.as_ptr()) };
        assert_eq!(result, FfiResult::Ok as i32);

        // Null token
        let result = unsafe { freeq_win_set_web_token(handle, std::ptr::null()) };
        assert_eq!(result, FfiResult::InvalidArgument as i32);

        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_operations_not_connected() {
        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };

        let channel = CString::new("#test").unwrap();
        let result = unsafe { freeq_win_join(handle, channel.as_ptr()) };
        assert_eq!(result, FfiResult::NotConnected as i32);

        let target = CString::new("#test").unwrap();
        let text = CString::new("hello").unwrap();
        let result = unsafe { freeq_win_send_message(handle, target.as_ptr(), text.as_ptr()) };
        assert_eq!(result, FfiResult::NotConnected as i32);

        let raw = CString::new("PING").unwrap();
        let result = unsafe { freeq_win_send_raw(handle, raw.as_ptr()) };
        assert_eq!(result, FfiResult::NotConnected as i32);

        let result = unsafe { freeq_win_disconnect(handle) };
        assert_eq!(result, FfiResult::NotConnected as i32);

        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_null_args_return_invalid_argument() {
        let config = make_config(r#"{"server":"127.0.0.1:6667","nick":"test"}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };

        // For these, handle is valid but args are null — we expect InvalidArgument
        // (but join/send check handle first, then null, then NotConnected)
        // Since the client isn't connected, the null check comes before NotConnected
        let result = unsafe { freeq_win_join(handle, std::ptr::null()) };
        assert_eq!(result, FfiResult::InvalidArgument as i32);

        let text = CString::new("hello").unwrap();
        let result = unsafe { freeq_win_send_message(handle, std::ptr::null(), text.as_ptr()) };
        assert_eq!(result, FfiResult::InvalidArgument as i32);

        let result = unsafe { freeq_win_send_raw(handle, std::ptr::null()) };
        assert_eq!(result, FfiResult::InvalidArgument as i32);

        unsafe { freeq_win_destroy_client(handle) };
    }

    #[test]
    fn test_free_null_string() {
        // Should not crash
        unsafe { freeq_win_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn test_config_defaults() {
        // Minimal config — server and nick should get defaults
        let config = make_config(r#"{}"#);
        let handle = unsafe { freeq_win_create_client(config.as_ptr()) };
        assert_ne!(handle, 0);

        let ptr = unsafe { freeq_win_get_snapshot_json(handle) };
        let json_str = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["server"], "127.0.0.1:6667");
        assert_eq!(parsed["nick"], "freeq_user");

        unsafe { freeq_win_free_string(ptr) };
        unsafe { freeq_win_destroy_client(handle) };
    }
}
