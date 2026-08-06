mod app;
mod config;
mod editor;
mod ui;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event as CrosstermEvent};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use editor::EditAction;
use freeq_sdk::auth::{ChallengeSigner, KeySigner, PdsSessionSigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::DidResolver;
use freeq_sdk::event::Event;
use freeq_sdk::oauth;
use freeq_sdk::pds;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::app::App;

/// Minimal TUI client for IRC with AT Protocol authentication.
///
/// Just run `freeq-tui` to connect to irc.freeq.at with TLS.
/// Settings are saved to ~/.config/freeq/tui.toml and channels
/// are restored from your last session.
#[derive(Parser, Debug)]
#[command(name = "freeq-tui", version, about)]
struct Cli {
    /// Server address (host:port). Default: irc.freeq.at:6697
    #[arg(short = 's', long)]
    server: Option<String>,

    /// IRC nickname. Default: derived from handle or system username.
    #[arg(short = 'n', long)]
    nick: Option<String>,

    /// Connect with TLS (auto-detected for port 6697).
    #[arg(long)]
    tls: bool,

    /// Skip TLS certificate verification (for self-signed certs).
    #[arg(long)]
    tls_insecure: bool,

    /// Bluesky handle (e.g. alice.bsky.social).
    /// Opens browser for OAuth authorization (no password needed).
    /// If --app-password is also given, uses app-password auth instead.
    #[arg(long)]
    handle: Option<String>,

    /// App password for Bluesky authentication (legacy, skips OAuth).
    /// Can also be set via ATP_APP_PASSWORD env var.
    #[arg(long, env = "ATP_APP_PASSWORD")]
    app_password: Option<String>,

    /// DID to authenticate as (alternative to --handle, for crypto auth).
    #[arg(long)]
    did: Option<String>,

    /// Path to hex-encoded private key file (for crypto auth).
    #[arg(long)]
    key_file: Option<String>,

    /// Key type: secp256k1 (default) or ed25519.
    #[arg(long, default_value = "secp256k1")]
    key_type: String,

    /// Generate a new keypair for testing (crypto auth).
    #[arg(long)]
    gen_key: bool,

    /// Connect via iroh (QUIC, encrypted, NAT-traversing).
    /// Provide the server's iroh endpoint address instead of host:port.
    #[arg(long)]
    iroh_addr: Option<String>,

    /// Use vi keybindings for input editing (default: emacs).
    #[arg(long)]
    vi: bool,

    /// Force re-authentication (clears cached OAuth session).
    #[arg(long)]
    reauth: bool,

    /// Auto-join channels on connect (comma-separated).
    /// Example: -c '#hello,#general'
    #[arg(short = 'c', long = "channel")]
    channels: Option<String>,

    /// Send a message to a channel and exit (non-interactive).
    /// Requires -c to specify the channel.
    /// Example: --send "hello world" -c '#freeq'
    #[arg(long)]
    send: Option<String>,

    /// Save current CLI args as defaults in config file.
    #[arg(long)]
    save_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load persistent config + session
    let cfg = config::Config::load();
    let session = config::Session::load();

    // --save-config: persist current CLI args and exit
    if cli.save_config {
        let mut new_cfg = cfg.clone();
        if let Some(ref s) = cli.server {
            new_cfg.server = Some(s.clone());
        }
        if let Some(ref n) = cli.nick {
            new_cfg.nick = Some(n.clone());
        }
        if let Some(ref h) = cli.handle {
            new_cfg.handle = Some(h.clone());
        }
        if cli.tls {
            new_cfg.tls = Some(true);
        }
        if cli.tls_insecure {
            new_cfg.tls_insecure = Some(true);
        }
        if cli.vi {
            new_cfg.vi = Some(true);
        }
        if let Some(ref ch) = cli.channels {
            new_cfg.channels = Some(
                ch.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            );
        }
        if let Some(ref a) = cli.iroh_addr {
            new_cfg.iroh_addr = Some(a.clone());
        }
        new_cfg.save();
        let path = dirs::config_dir()
            .unwrap_or_default()
            .join("freeq")
            .join("tui.toml");
        eprintln!("Config saved to {}", path.display());
        return Ok(());
    }

    // Decide: interactive form vs. auto-connect
    // Show form when: no CLI args AND no saved handle (first run or guest-only history)
    // Auto-connect when: CLI args given OR saved session has a handle
    let resolved =
        if !config::has_explicit_cli_args(&cli) && !config::has_saved_session(&cfg, &session) {
            // First run or no saved identity → interactive setup
            match config::interactive_setup(&cfg, &session) {
                Some(r) => r,
                None => return Ok(()), // user cancelled
            }
        } else if config::has_explicit_cli_args(&cli) {
            // Explicit CLI args → merge normally, no form
            let r = config::Resolved::merge(&cli, &cfg, &session);
            eprintln!(
                "freeq-tui — server: {}, nick: {}, channels: {}",
                r.server,
                r.nick,
                if r.channels.is_empty() {
                    "(none)".to_string()
                } else {
                    r.channels.join(", ")
                },
            );
            if let Some(ref h) = r.handle {
                eprintln!("  handle: {h}");
            }
            r
        } else {
            // Saved session with handle → auto-reconnect
            let r = config::Resolved::merge(&cli, &cfg, &session);
            if let Some(ref h) = r.handle {
                eprintln!("freeq-tui — reconnecting as 🦋 {h} to {}", r.server);
            } else {
                eprintln!("freeq-tui — reconnecting to {}", r.server);
            }
            eprintln!(
                "  nick: {}, channels: {}",
                r.nick,
                if r.channels.is_empty() {
                    "(none)".to_string()
                } else {
                    r.channels.join(", ")
                },
            );
            r
        };

    // Build a CLI-like struct with resolved values for build_signer
    let effective_cli = Cli {
        server: Some(resolved.server.clone()),
        nick: Some(resolved.nick.clone()),
        handle: resolved.handle.clone(),
        tls: resolved.tls,
        tls_insecure: resolved.tls_insecure,
        vi: resolved.vi,
        channels: if resolved.channels.is_empty() {
            None
        } else {
            Some(resolved.channels.join(","))
        },
        iroh_addr: resolved.iroh_addr.clone(),
        app_password: cli.app_password.clone(),
        did: cli.did.clone(),
        key_file: cli.key_file.clone(),
        key_type: cli.key_type.clone(),
        gen_key: cli.gen_key,
        reauth: cli.reauth,
        send: cli.send.clone(),
        save_config: false,
    };

    let (signer, media_uploader) = build_signer(&effective_cli).await?;

    let auth_status = if signer.is_some() {
        "authenticating"
    } else {
        "guest"
    };

    // Transport priority: iroh > TCP/TLS
    let iroh_addr = if let Some(ref addr) = resolved.iroh_addr {
        Some(addr.clone())
    } else {
        eprintln!("Probing {} for iroh transport...", resolved.server);
        match client::discover_iroh_id(&resolved.server, resolved.tls, resolved.tls_insecure).await
        {
            Some(id) => {
                eprintln!("  Server advertises iroh: {}", &id[..16.min(id.len())]);
                Some(id)
            }
            None => {
                eprintln!(
                    "  No iroh available, using {}",
                    if resolved.tls { "TLS" } else { "TCP" }
                );
                None
            }
        }
    };

    let conn = if let Some(ref iroh_addr) = iroh_addr {
        eprintln!(
            "Connecting via iroh to {} as {} ({auth_status})...",
            &iroh_addr[..16.min(iroh_addr.len())],
            resolved.nick
        );
        client::establish_iroh_connection(iroh_addr).await?
    } else {
        eprintln!(
            "Connecting to {} as {} ({auth_status})...",
            resolved.server, resolved.nick
        );
        if resolved.tls {
            eprintln!("  (TLS enabled)");
        }

        client::establish_connection(&ConnectConfig {
            server_addr: resolved.server.clone(),
            nick: resolved.nick.clone(),
            user: resolved.nick.clone(),
            realname: "freeq tui".to_string(),
            tls: resolved.tls,
            tls_insecure: resolved.tls_insecure,
            web_token: None,
            websocket_url: None,
        })
        .await?
    };

    let connect_config = ConnectConfig {
        server_addr: iroh_addr.as_deref().unwrap_or(&resolved.server).to_string(),
        nick: resolved.nick.clone(),
        user: resolved.nick.clone(),
        realname: "freeq tui".to_string(),
        tls: resolved.tls,
        tls_insecure: resolved.tls_insecure,
        web_token: None,
        websocket_url: None,
    };

    let (mut handle, mut events) =
        client::connect_with_stream(conn, connect_config.clone(), signer.clone());

    // Auto-join channels
    for ch in &resolved.channels {
        let _ = handle.join(ch).await;
    }

    // ── Non-interactive send mode ──────────────────────────────────────
    if let Some(ref msg) = cli.send {
        let target_channel = resolved
            .channels
            .first()
            .ok_or_else(|| anyhow::anyhow!("--send requires -c <channel>"))?
            .clone();

        // Wait for registration + channel join to complete
        let mut registered = false;
        let mut joined = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);

        while !joined {
            tokio::select! {
                event = events.recv() => {
                    match event {
                        Some(Event::Registered { .. }) => {
                            registered = true;
                            eprintln!("  registered");
                        }
                        Some(Event::NamesEnd { channel })
                            if channel.eq_ignore_ascii_case(&target_channel) => {
                                joined = true;
                                eprintln!("  joined {channel}");
                            }
                        Some(Event::AuthFailed { reason }) => {
                            anyhow::bail!("Authentication failed: {reason}");
                        }
                        Some(Event::Disconnected { reason }) => {
                            anyhow::bail!("Disconnected: {reason}");
                        }
                        None => {
                            anyhow::bail!("Connection closed unexpectedly");
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if registered && !joined {
                        anyhow::bail!("Timed out waiting to join {target_channel} (registered but couldn't join — check channel policy)");
                    }
                    anyhow::bail!("Timed out waiting for registration");
                }
            }
        }

        // Send the message
        handle
            .send_tagged(&target_channel, msg, std::collections::HashMap::new())
            .await?;
        eprintln!("  sent to {target_channel}: {msg}");

        // Brief pause to let the server process and broadcast
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        handle.quit(Some("")).await?;
        eprintln!("done");
        return Ok(());
    }

    // Detect terminal image capabilities BEFORE entering raw mode
    #[cfg(feature = "inline-images")]
    let picker = match ratatui_image::picker::Picker::from_query_stdio() {
        Ok(p) => {
            eprintln!("Terminal image support: {:?}", p.capabilities());
            Some(p)
        }
        Err(_) => {
            eprintln!("No terminal image support; using text-only mode");
            None
        }
    };

    // Setup terminal
    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(&resolved.nick, resolved.vi);
    if iroh_addr.is_some() {
        app.transport = app::Transport::Iroh;
        app.iroh_endpoint_id = iroh_addr.clone();
    } else if resolved.tls {
        app.transport = app::Transport::Tls;
    } else {
        app.transport = app::Transport::Tcp;
    }
    app.server_addr = resolved.server.clone();
    app.connected_at = Some(std::time::Instant::now());
    app.media_uploader = media_uploader;
    #[cfg(feature = "inline-images")]
    {
        app.picker = picker;
    }

    let mut reconnect_info = Some(ReconnectInfo {
        config: connect_config,
        signer: signer.clone(),
        channels: resolved.channels.clone(),
        _iroh_addr: iroh_addr.clone(),
    });

    let result = run_app(
        &mut terminal,
        &mut app,
        &mut handle,
        &mut events,
        &mut reconnect_info,
    )
    .await;

    // Save session state on exit (channels, server, nick, handle)
    let open_channels: Vec<String> = app
        .buffers
        .keys()
        .filter(|k| k.starts_with('#') || k.starts_with('&'))
        .cloned()
        .collect();
    config::Session {
        server: Some(resolved.server),
        nick: Some(app.nick.clone()),
        handle: resolved.handle,
        channels: open_channels,
    }
    .save();

    // Restore terminal
    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;

    result
}

type SignerResult = (Option<Arc<dyn ChallengeSigner>>, Option<app::MediaUploader>);

fn make_oauth_uploader(session: &oauth::OAuthSession) -> app::MediaUploader {
    app::MediaUploader {
        did: session.did.clone(),
        pds_url: session.pds_url.clone(),
        access_token: session.access_token.clone(),
        dpop_key: Some(session.dpop_key.clone()),
        dpop_nonce: session.dpop_nonce.clone(),
    }
}

async fn build_signer(cli: &Cli) -> Result<SignerResult> {
    // Option 1: Bluesky login via handle
    if let Some(ref handle) = cli.handle {
        if let Some(ref password) = cli.app_password {
            // Legacy: app-password auth
            eprintln!("Authenticating to Bluesky as {handle} (app password)...");
            let resolver = DidResolver::http();
            let (session, pds_url) = pds::create_session(handle, password, &resolver).await?;
            eprintln!("  DID: {}", session.did);
            eprintln!("  Handle: {}", session.handle);
            eprintln!("  PDS: {pds_url}");
            let uploader = app::MediaUploader {
                did: session.did.clone(),
                pds_url: pds_url.clone(),
                access_token: session.access_jwt.clone(),
                dpop_key: None,
                dpop_nonce: None,
            };
            return Ok((
                Some(Arc::new(PdsSessionSigner::new_with_refresh(
                    session.did,
                    session.access_jwt,
                    session.refresh_jwt,
                    pds_url,
                ))),
                Some(uploader),
            ));
        } else {
            // Try cached session first (unless --reauth)
            let cache_path = oauth::default_session_path(handle);
            if cli.reauth {
                eprintln!("Re-authenticating (--reauth)...");
                let _ = std::fs::remove_file(&cache_path);
            }
            if cache_path.exists() {
                eprintln!("Found cached session, validating...");
                match oauth::OAuthSession::load(&cache_path) {
                    Ok(cached) => match cached.validate().await {
                        Ok(session) => {
                            eprintln!("  Cached session valid for {}", session.did);
                            let _ = session.save(&cache_path);
                            let uploader = make_oauth_uploader(&session);
                            return Ok((
                                Some(Arc::new(PdsSessionSigner::new_oauth(
                                    session.did,
                                    session.access_token,
                                    session.pds_url,
                                    session.dpop_key,
                                    session.dpop_nonce,
                                ))),
                                Some(uploader),
                            ));
                        }
                        Err(e) => {
                            eprintln!("  Cached session expired: {e}");
                            let _ = std::fs::remove_file(&cache_path);
                        }
                    },
                    Err(e) => {
                        eprintln!("  Failed to load cache: {e}");
                        let _ = std::fs::remove_file(&cache_path);
                    }
                }
            }

            // OAuth flow — opens browser, no password needed
            eprintln!("Logging in as {handle} via OAuth...");
            let session = oauth::login(handle).await?;
            eprintln!("  DID: {}", session.did);
            eprintln!("  Handle: {}", session.handle);
            eprintln!("  PDS: {}", session.pds_url);

            if let Err(e) = session.save(&cache_path) {
                eprintln!("  Warning: failed to cache session: {e}");
            } else {
                eprintln!("  Session cached to {}", cache_path.display());
            }

            // Save handle to config so future `freeq-tui` (no args) auto-reconnects
            let mut cfg = config::Config::load();
            if cfg.handle.as_deref() != Some(handle) {
                cfg.handle = Some(handle.to_string());
                cfg.save();
            }

            let uploader = make_oauth_uploader(&session);
            return Ok((
                Some(Arc::new(PdsSessionSigner::new_oauth(
                    session.did,
                    session.access_token,
                    session.pds_url,
                    session.dpop_key,
                    session.dpop_nonce,
                ))),
                Some(uploader),
            ));
        }
    }

    // Option 2: Crypto auth with generated key
    if cli.gen_key {
        let private_key = match cli.key_type.as_str() {
            "ed25519" => PrivateKey::generate_ed25519(),
            _ => PrivateKey::generate_secp256k1(),
        };
        let multibase = private_key.public_key_multibase();
        let did = cli
            .did
            .clone()
            .unwrap_or_else(|| "did:plc:generated-test-key".to_string());
        eprintln!("Generated {} keypair:", cli.key_type);
        eprintln!("  DID: {did}");
        eprintln!("  Public key (multibase): {multibase}");
        return Ok((Some(Arc::new(KeySigner::new(did, private_key))), None));
    }

    // Option 3: Crypto auth with DID + key file
    if let Some(ref did) = cli.did {
        let private_key = if let Some(ref path) = cli.key_file {
            let hex_str = std::fs::read_to_string(path)?.trim().to_string();
            let bytes =
                hex::decode(&hex_str).map_err(|e| anyhow::anyhow!("Bad hex in key file: {e}"))?;
            match cli.key_type.as_str() {
                "ed25519" => PrivateKey::ed25519_from_bytes(&bytes)?,
                _ => PrivateKey::secp256k1_from_bytes(&bytes)?,
            }
        } else {
            eprintln!("Warning: --did without --key-file. Generating ephemeral key.");
            match cli.key_type.as_str() {
                "ed25519" => PrivateKey::generate_ed25519(),
                _ => PrivateKey::generate_secp256k1(),
            }
        };
        return Ok((
            Some(Arc::new(KeySigner::new(did.clone(), private_key))),
            None,
        ));
    }

    // No auth — guest mode
    Ok((None, None))
}

/// State needed to reconnect after a disconnect.
struct ReconnectInfo {
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    channels: Vec<String>,
    _iroh_addr: Option<String>,
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    handle: &mut client::ClientHandle,
    events: &mut tokio::sync::mpsc::Receiver<Event>,
    reconnect_info: &mut Option<ReconnectInfo>,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        // Check for encoding errors from image rendering
        #[cfg(feature = "inline-images")]
        {
            for proto in app.image_protos.values_mut() {
                if let Some(Err(e)) = proto.last_encoding_result() {
                    tracing::warn!("Image encoding error: {e}");
                }
            }
        }

        let has_crossterm_event =
            tokio::task::block_in_place(|| event::poll(Duration::from_millis(16)))?;

        if has_crossterm_event {
            let evt = tokio::task::block_in_place(event::read)?;
            if let CrosstermEvent::Key(key) = evt {
                // Close net popup on Escape
                if app.show_net_popup {
                    use crossterm::event::KeyCode;
                    if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                        app.show_net_popup = false;
                        continue;
                    }
                }
                // Handle pending URL prompt (Enter to open, anything else to dismiss)
                if app.pending_url.is_some() {
                    use crossterm::event::KeyCode;
                    if matches!(key.code, KeyCode::Enter) {
                        if let Some(url) = app.pending_url.take() {
                            match open::that(&url) {
                                Ok(_) => app.status_msg("Opened URL in browser."),
                                Err(e) => app.status_msg(&format!("Failed to open URL: {e}")),
                            }
                        }
                    } else {
                        app.pending_url = None;
                        app.status_msg("URL dismissed.");
                    }
                    continue;
                }
                let action = app.editor.handle_key(key);
                match action {
                    EditAction::Submit => {
                        let input = app.input_take();
                        if !input.is_empty() {
                            process_input(app, handle, &input).await?;
                        }
                    }
                    EditAction::HistoryUp => app.history_up(),
                    EditAction::HistoryDown => app.history_down(),
                    EditAction::Complete => try_nick_complete(app),
                    EditAction::NextBuffer => app.next_buffer(),
                    EditAction::PrevBuffer => app.prev_buffer(),
                    EditAction::ScrollUp(n) => {
                        let (auto_fetch_target, auto_fetch_anchor) = {
                            if let Some(buf) = app.buffers.get_mut(&app.active_buffer) {
                                buf.scroll = buf.scroll.saturating_add(n);
                                // Heuristic: when scroll puts us within ~20 lines
                                // of the top of what's loaded, request more.
                                let near_top =
                                    buf.scroll.saturating_add(20) >= buf.messages.len() as u16;
                                let eligible = near_top
                                    && !buf.history_in_flight
                                    && !buf.history_exhausted
                                    && (buf.name.starts_with('#') || buf.name.starts_with('&'));
                                let oldest = if eligible {
                                    buf.oldest_msgid().map(String::from)
                                } else {
                                    None
                                };
                                if let Some(anchor) = oldest {
                                    buf.history_in_flight = true;
                                    (Some(buf.name.clone()), Some(anchor))
                                } else {
                                    (None, None)
                                }
                            } else {
                                (None, None)
                            }
                        };
                        if let (Some(target), Some(anchor)) = (auto_fetch_target, auto_fetch_anchor)
                            && handle.history_before(&target, &anchor, 50).await.is_err()
                            && let Some(buf) = app.buffers.get_mut(&app.active_buffer)
                        {
                            // Failed to send — clear the flag so a future
                            // scroll attempt can retry.
                            buf.history_in_flight = false;
                        }
                    }
                    EditAction::ScrollDown(n) => {
                        if let Some(buf) = app.buffers.get_mut(&app.active_buffer) {
                            buf.scroll = buf.scroll.saturating_sub(n);
                        }
                    }
                    EditAction::Quit => {
                        let _ = handle.quit(Some("bye")).await;
                        // Give the background writer task time to flush QUIT to the server.
                        // Without this, the process exits before the TCP write completes
                        // and the server never sees the QUIT — leaving a ghost session
                        // until ping timeout.
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        app.should_quit = true;
                    }
                    EditAction::None => {}
                }
            }
        }

        // Drain IRC events
        while let Ok(evt) = events.try_recv() {
            process_irc_event(app, evt, handle);
        }

        // A WHOIS answer drained above may have named a peer we're holding a
        // first DM for — send it now, signed, rather than a tick later.
        flush_pending_dms(app, handle).await;

        // Drain P2P events
        {
            let mut p2p_evts = Vec::new();
            if let Some(ref mut p2p_rx) = app.p2p_event_rx {
                while let Ok(evt) = p2p_rx.try_recv() {
                    p2p_evts.push(evt);
                }
            }
            for evt in p2p_evts {
                process_p2p_event(app, evt);
            }
        }

        // Backfill: when a DM buffer is the active one and we haven't yet
        // pulled its history this session, request it once. Channels get
        // history pushed on JOIN; DMs have no JOIN, so opening one would
        // otherwise show only messages that arrive live.
        maybe_fetch_history(app, handle).await;

        // Drain background task results
        if let Some(mut bg_rx) = app.bg_result_rx.take() {
            while let Ok(result) = bg_rx.try_recv() {
                match result {
                    crate::app::BgResult::VerifyLines(buf, lines) => {
                        for line in &lines {
                            app.buffer_mut(&buf).push_system(line);
                        }
                    }
                    crate::app::BgResult::ProfileLines(buf, lines, avatar_url) => {
                        for line in &lines {
                            // Skip the 🖼 avatar-URL line — we render it as inline image below
                            if avatar_url.is_some() && line.starts_with("  🖼") {
                                continue;
                            }
                            app.buffer_mut(&buf).push_system(&format!("*** {line}"));
                        }
                        // Add avatar as inline image if available
                        if let Some(ref url) = avatar_url {
                            app.buffer_mut(&buf).push_system("***");
                            // Set image_url on the message we just pushed
                            if let Some(last) = app.buffer_mut(&buf).messages.back_mut() {
                                last.image_url = Some(url.clone());
                            }
                        }
                    }
                }
            }
            app.bg_result_rx = Some(bg_rx);
        }

        // Auto-reconnect logic
        if app.reconnect_pending {
            if app.reconnect_at.is_none() {
                // Schedule first reconnect attempt
                app.reconnect_at = Some(std::time::Instant::now() + app.reconnect_delay);
                let secs = app.reconnect_delay.as_secs();
                app.connection_state = format!("reconnecting in {secs}s");
                app.status_msg(&format!("Will reconnect in {secs}s..."));
            }

            if let Some(at) = app.reconnect_at
                && std::time::Instant::now() >= at
            {
                app.reconnect_at = None;
                app.reconnect_pending = false;

                if let Some(ri) = reconnect_info.as_ref() {
                    app.status_msg("Reconnecting...");
                    app.connection_state = "connecting".to_string();

                    match client::establish_connection(&ri.config).await {
                        Ok(conn) => {
                            let (new_handle, new_events) = client::connect_with_stream(
                                conn,
                                ri.config.clone(),
                                ri.signer.clone(),
                            );
                            *handle = new_handle;
                            *events = new_events;

                            // Re-join channels
                            for ch in &ri.channels {
                                let _ = handle.join(ch).await;
                            }
                            // Also rejoin any channels we were in (from buffers)
                            for buf_name in app.buffers.keys() {
                                if (buf_name.starts_with('#') || buf_name.starts_with('&'))
                                    && !ri.channels.iter().any(|c| c.eq_ignore_ascii_case(buf_name))
                                {
                                    let _ = handle.join(buf_name).await;
                                }
                            }

                            app.reconnect_delay = Duration::from_secs(1);
                            app.connected_at = Some(std::time::Instant::now());
                            app.status_msg("Reconnected!");
                        }
                        Err(e) => {
                            // Exponential backoff: 1s, 2s, 4s, 8s, ... capped at 60s
                            app.reconnect_delay =
                                (app.reconnect_delay * 2).min(Duration::from_secs(60));
                            let secs = app.reconnect_delay.as_secs();
                            app.connection_state = format!("reconnecting in {secs}s");
                            app.status_msg(&format!(
                                "Reconnect failed: {e}. Retrying in {secs}s..."
                            ));
                            app.reconnect_pending = true;
                            app.reconnect_at =
                                Some(std::time::Instant::now() + app.reconnect_delay);
                        }
                    }
                } else {
                    app.status_msg("Cannot reconnect: no connection info available");
                    app.should_quit = true;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn process_p2p_event(app: &mut App, event: freeq_sdk::p2p::P2pEvent) {
    use freeq_sdk::p2p::P2pEvent;
    match event {
        P2pEvent::EndpointReady { endpoint_id } => {
            app.status_msg(&format!("P2P endpoint ready: {endpoint_id}"));
        }
        P2pEvent::PeerConnected { peer_id } => {
            let short = &peer_id[..8.min(peer_id.len())];
            let buffer_key = format!("p2p:{short}");
            app.buffer_mut(&buffer_key)
                .push_system(&format!("🔗 Peer connected: {peer_id}"));
            app.status_msg(&format!("P2P peer connected: {short}…"));
        }
        P2pEvent::PeerDisconnected { peer_id } => {
            let short = &peer_id[..8.min(peer_id.len())];
            let buffer_key = format!("p2p:{short}");
            app.buffer_mut(&buffer_key)
                .push_system(&format!("🔌 Peer disconnected: {peer_id}"));
        }
        P2pEvent::DirectMessage { peer_id, text } => {
            let short = &peer_id[..8.min(peer_id.len())];
            let buffer_key = format!("p2p:{short}");
            app.chat_msg(&buffer_key, &format!("{short}…"), &text);
        }
        P2pEvent::Error { message } => {
            app.status_msg(&format!("P2P error: {message}"));
        }
    }
}

fn process_irc_event(app: &mut App, event: Event, _handle: &client::ClientHandle) {
    match event {
        // Nick<->DID binding learned. Adopted in the TUI's DID-DM pass;
        // ignored until then (this keeps the build from breaking, no more).
        Event::MemberDid { nick, did } => {
            // A nick↔DID binding was learned: remember the display name and
            // fold any nick-keyed DM thread into the DID-keyed one.
            app.record_member_did(&nick, &did);
        }
        Event::Connected => {
            app.connection_state = "connected".to_string();
            app.status_msg(&format!(
                "Connected to server via {}",
                app.transport.description()
            ));
        }
        Event::Registered { nick } => {
            app.connection_state = "registered".to_string();
            app.nick = nick.clone();
            app.status_msg(&format!("Registered as {nick}"));
        }
        Event::Authenticated { did } => {
            app.authenticated_did = Some(did.clone());
            app.status_msg(&format!("Authenticated as {did}"));
        }
        Event::AuthFailed { reason } => {
            app.status_msg(&format!("Authentication failed: {reason}"));
        }
        Event::Joined { channel, nick, .. } => {
            let cloak = app
                .nick_hosts
                .get(&nick.to_lowercase())
                .filter(|h| h.starts_with("freeq/"))
                .cloned();
            let buf = app.buffer_mut(&channel);
            if !buf.nicks.iter().any(|n| {
                let bare = n.trim_start_matches(['@', '+']);
                bare == nick
            }) {
                buf.nicks.push(nick.clone());
            }
            match cloak {
                Some(host) => buf.push_system(&format!("{nick} [{host}] has joined")),
                None => buf.push_system(&format!("{nick} has joined")),
            }
            if nick == app.nick {
                app.active_buffer = channel.to_lowercase();
            }
        }
        Event::Parted { channel, nick } => {
            let buf = app.buffer_mut(&channel);
            buf.nicks.retain(|n| {
                let bare = n.trim_start_matches(['@', '+']);
                bare != nick
            });
            buf.push_system(&format!("{nick} has left"));
        }
        Event::Message {
            from,
            target,
            text,
            tags,
            dm_key,
            ..
        } => {
            // DID is the identity. Render our own messages under our current
            // nick no matter which client alias sent them — a TUI as `-n nap`,
            // a web session as the handle nick `zapnap` — so one DID reads as
            // one person, and /edit and /delete (which select own messages by
            // nick) then find them all. Guarded by the `account` tag equalling
            // our DID so a peer with no account tag is never mistaken for us.
            let from = if app
                .authenticated_did
                .as_deref()
                .is_some_and(|my| tags.get("account").map(String::as_str) == Some(my))
            {
                app.nick.clone()
            } else {
                from
            };
            // One conversation, one buffer: channels key by name; DMs key
            // by the SDK's dm_key (peer DID when known, else nick) so an
            // echo and the peer's reply land in the same thread.
            let buf_name = if target.starts_with('#') || target.starts_with('&') {
                target.clone()
            } else {
                dm_key.clone().unwrap_or_else(|| {
                    if from == app.nick {
                        target.clone()
                    } else {
                        from.clone()
                    }
                })
            };
            // Try E2EE decryption if we have a key for this channel
            let (text, was_encrypted) = {
                let buf_key = crate::app::buffer_key(&buf_name);
                if let Some(key) = app.channel_keys.get(&buf_key) {
                    if freeq_sdk::e2ee::is_encrypted(&text) {
                        match freeq_sdk::e2ee::decrypt(key, &text) {
                            Ok(plaintext) => (plaintext, true),
                            Err(_) => {
                                // Wrong key or tampered — show error inline
                                (
                                    "🔒 [encrypted message — wrong key or corrupted]".to_string(),
                                    false,
                                )
                            }
                        }
                    } else {
                        // We have a key but this message isn't encrypted
                        // (could be from a user who hasn't enabled E2EE)
                        (text.clone(), false)
                    }
                } else if freeq_sdk::e2ee::is_encrypted(&text) {
                    // Encrypted but we don't have the key
                    (
                        "🔒 [encrypted message — use /encrypt <passphrase> to decrypt]".to_string(),
                        false,
                    )
                } else {
                    (text.clone(), false)
                }
            };
            let _ = was_encrypted; // may be used later for UI indicators

            let timestamp = format_timestamp(&tags);
            let timestamp_ms = parse_timestamp_ms(&tags);
            let batch_id = tags.get("batch");
            // Validate untrusted tag values before they enter our state.
            // A malicious peer could craft msgids/reply-targets containing
            // CR/LF (IRC command injection), whitespace (param-splitting),
            // or terminal escapes (cursor takeover when displayed).
            let msgid = tags
                .get("msgid")
                .filter(|v| crate::app::is_valid_msgid(v))
                .cloned();
            let reply_to = tags
                .get("+reply")
                .filter(|v| crate::app::is_valid_msgid(v))
                .cloned();
            let (is_signed, account) = signature_of(&tags);
            // Join replay collapses an edited message into one row with no
            // `+draft/edit`; the server's `+freeq.at/edited` tag is the only
            // thing that says the text isn't the original.
            let replay_edited = tags.get("+freeq.at/edited").is_some_and(|v| v == "1");

            // Pin/unpin: server sends a NOTICE CTCP ACTION with a tag. Update
            // the channel's pin set; let the action message itself fall through
            // so the user sees who pinned what.
            if target.starts_with('#') || target.starts_with('&') {
                if let Some(pinned_id) = tags
                    .get("+freeq.at/pin")
                    .filter(|v| crate::app::is_valid_msgid(v))
                {
                    app.buffer_mut(&target).add_pinned(pinned_id);
                } else if let Some(unpinned_id) = tags
                    .get("+freeq.at/unpin")
                    .filter(|v| crate::app::is_valid_msgid(v))
                {
                    app.buffer_mut(&target).pinned.remove(unpinned_id);
                }
            }

            // Edit message: rewrite the original in place; don't push a new line.
            if let Some(original_msgid) = tags
                .get("+draft/edit")
                .filter(|v| crate::app::is_valid_msgid(v))
            {
                let applied = app.apply_edit(
                    &from,
                    batch_id.map(|s| s.as_str()),
                    &buf_name,
                    original_msgid,
                    msgid.as_deref(),
                    &text,
                );
                // Original nowhere on screen (outside the replay window, or
                // we joined after it was sent): show the current text as its
                // own line rather than dropping the content — keyed by the
                // message's identity, the original msgid, never the
                // revision's wire id.
                if !applied {
                    push_line_to_buffer(
                        app,
                        batch_id,
                        &buf_name,
                        timestamp_ms,
                        crate::app::BufferLine {
                            timestamp: timestamp.clone(),
                            from: from.clone(),
                            text: text.clone(),
                            is_system: false,
                            image_url: None,
                            msgid: Some(original_msgid.clone()),
                            is_edited: true,
                            is_deleted: false,
                            reply_to: reply_to.clone(),
                            edit_of: Some(original_msgid.clone()),
                            is_signed,
                            account: account.clone(),
                        },
                    );
                }
                return;
            }

            // Check for media attachment in tags
            let media = freeq_sdk::media::MediaAttachment::from_tags(&tags);

            // Detect CTCP ACTION (/me)
            if text.starts_with('\x01') && text.ends_with('\x01') {
                let inner = &text[1..text.len() - 1];
                if let Some(action) = inner.strip_prefix("ACTION ") {
                    push_line_to_buffer(
                        app,
                        batch_id,
                        &buf_name,
                        timestamp_ms,
                        crate::app::BufferLine {
                            timestamp: timestamp.clone(),
                            from: String::new(),
                            text: format!("* {from} {action}"),
                            is_system: true,
                            image_url: None,
                            msgid: msgid.clone(),
                            is_edited: replay_edited,
                            is_deleted: false,
                            reply_to: reply_to.clone(),
                            edit_of: None,
                            is_signed,
                            account: account.clone(),
                        },
                    );
                }
            } else if let Some(ref media) = media {
                // Rich media message
                let display = format_media_display(media);
                let img_url = if media.content_type.starts_with("image/") {
                    Some(media.url.clone())
                } else {
                    None
                };
                // Trigger background fetch if it's an image
                if let Some(ref url) = img_url {
                    fetch_image_if_needed(&app.image_cache, url);
                }
                push_line_to_buffer(
                    app,
                    batch_id,
                    &buf_name,
                    timestamp_ms,
                    crate::app::BufferLine {
                        timestamp: timestamp.clone(),
                        from: from.clone(),
                        text: display,
                        is_system: false,
                        image_url: img_url,
                        msgid: msgid.clone(),
                        is_edited: replay_edited,
                        is_deleted: false,
                        reply_to: reply_to.clone(),
                        edit_of: None,
                        is_signed,
                        account: account.clone(),
                    },
                );
            } else {
                // Check for link preview in tags
                let link_preview = freeq_sdk::media::LinkPreview::from_tags(&tags);
                if let Some(preview) = link_preview {
                    let display = format_link_preview(&preview);
                    push_line_to_buffer(
                        app,
                        batch_id,
                        &buf_name,
                        timestamp_ms,
                        crate::app::BufferLine {
                            timestamp: timestamp.clone(),
                            from: from.clone(),
                            text: display,
                            is_system: false,
                            image_url: None,
                            msgid: msgid.clone(),
                            is_edited: replay_edited,
                            is_deleted: false,
                            reply_to: reply_to.clone(),
                            edit_of: None,
                            is_signed,
                            account: account.clone(),
                        },
                    );
                } else {
                    push_line_to_buffer(
                        app,
                        batch_id,
                        &buf_name,
                        timestamp_ms,
                        crate::app::BufferLine {
                            timestamp: timestamp.clone(),
                            from: from.clone(),
                            text: text.clone(),
                            is_system: false,
                            image_url: None,
                            msgid: msgid.clone(),
                            is_edited: replay_edited,
                            is_deleted: false,
                            reply_to: reply_to.clone(),
                            edit_of: None,
                            is_signed,
                            account: account.clone(),
                        },
                    );

                    // Note: auto-fetch of link previews disabled.
                    // Use /preview <url> to manually fetch + share a preview.
                    // Auto-fetching arbitrary URLs from messages is a privacy/security risk
                    // (leaks IP to URL host, potential SSRF, sends messages on user's behalf).
                }
            }
        }
        Event::BatchStart {
            id,
            batch_type,
            target,
        } => {
            app.start_batch_typed(&id, &target, &batch_type);
        }
        Event::BatchEnd { id } => {
            app.end_batch(&id);
        }
        Event::TagMsg {
            from,
            target,
            tags,
            dm_key,
            ..
        } => {
            // Same conversation keying as Event::Message.
            let buf_name = if target.starts_with('#') || target.starts_with('&') {
                target.clone()
            } else {
                dm_key.clone().unwrap_or_else(|| {
                    if from == app.nick {
                        target.clone()
                    } else {
                        from.clone()
                    }
                })
            };
            // Delete: mark the target line as deleted; don't display a new line.
            if let Some(deleted_msgid) = tags
                .get("+draft/delete")
                .filter(|v| crate::app::is_valid_msgid(v))
            {
                let batch_id = tags.get("batch").map(|s| s.as_str());
                app.apply_delete(&from, batch_id, &buf_name, deleted_msgid);
                return;
            }
            // Handle reactions, added and withdrawn. Both keep the buffer's
            // reaction ledger current — that's what `/unreact` reads to find
            // which message a reaction of ours is on.
            let reacted = freeq_sdk::media::Reaction::from_tags(&tags).map(|r| (r.emoji, true));
            let unreacted = tags
                .get("+freeq.at/unreact")
                .map(|emoji| (emoji.clone(), false));
            if let Some((emoji, added)) = reacted.or(unreacted) {
                let target_msgid = tags
                    .get("+reply")
                    .filter(|v| crate::app::is_valid_msgid(v))
                    .cloned();
                let target_preview = target_msgid
                    .as_deref()
                    .and_then(|id| {
                        app.buffers
                            .get(&crate::app::buffer_key(&buf_name))?
                            .find_by_msgid(id)
                    })
                    .map(|line| {
                        let snippet: String = line.text.chars().take(40).collect();
                        if line.text.chars().count() > 40 {
                            format!(" → \"{snippet}…\"")
                        } else {
                            format!(" → \"{snippet}\"")
                        }
                    })
                    .unwrap_or_default();
                if let Some(ref id) = target_msgid {
                    let buf = app.buffer_mut(&buf_name);
                    if added {
                        buf.add_reaction(id, &from, &emoji);
                    } else {
                        buf.remove_reaction(id, &from, &emoji);
                    }
                }
                let verb = if added { "reacted" } else { "removed" };
                app.buffer_mut(&buf_name).push(crate::app::BufferLine {
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                    from: String::new(),
                    text: format!("  {from} {verb} {emoji}{target_preview}"),
                    is_system: true,
                    image_url: None,
                    msgid: None,
                    is_edited: false,
                    is_deleted: false,
                    reply_to: None,
                    edit_of: None,
                    is_signed: false,
                    account: None,
                });
            }
        }
        Event::ModeChanged {
            channel,
            mode,
            arg,
            set_by,
        } => {
            let msg = match &arg {
                Some(a) => format!("{set_by} sets mode {mode} {a}"),
                None => format!("{set_by} sets mode {mode}"),
            };
            app.buffer_mut(&channel).push_system(&msg);

            // Update nick prefixes for +o/-o/+v/-v
            if let Some(ref target_nick) = arg {
                let buf = app.buffer_mut(&channel);
                let bare = target_nick.trim_start_matches(['@', '+']);
                match mode.as_str() {
                    "+o" => {
                        // Remove any existing entry, add with @
                        buf.nicks
                            .retain(|n| n.trim_start_matches(['@', '+']) != bare);
                        buf.nicks.push(format!("@{bare}"));
                    }
                    "-o" => {
                        buf.nicks
                            .retain(|n| n.trim_start_matches(['@', '+']) != bare);
                        buf.nicks.push(bare.to_string());
                    }
                    "+v" => {
                        // Only add + if not already an op
                        let was_op = buf.nicks.iter().any(|n| n == &format!("@{bare}"));
                        if !was_op {
                            buf.nicks
                                .retain(|n| n.trim_start_matches(['@', '+']) != bare);
                            buf.nicks.push(format!("+{bare}"));
                        }
                    }
                    "-v" => {
                        let was_op = buf.nicks.iter().any(|n| n == &format!("@{bare}"));
                        if !was_op {
                            buf.nicks
                                .retain(|n| n.trim_start_matches(['@', '+']) != bare);
                            buf.nicks.push(bare.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        Event::Kicked {
            channel,
            nick,
            by,
            reason,
        } => {
            // Case-insensitive nick comparison (IRC nicks are case-insensitive)
            if nick.to_lowercase() == app.nick.to_lowercase() {
                // WE were kicked — show message and leave the channel
                app.buffer_mut(&channel)
                    .push_system(&format!("You were kicked by {by} ({reason})"));
                app.status_msg(&format!("Kicked from {channel} by {by} ({reason})"));
                // Remove the channel buffer so we stop showing it
                app.remove_buffer(&channel);
            } else {
                // Someone else was kicked — just remove them from nick list
                let msg = format!("{nick} was kicked by {by} ({reason})");
                let buf = app.buffer_mut(&channel);
                buf.nicks.retain(|n| {
                    let bare = n.trim_start_matches(['@', '+']);
                    bare.to_lowercase() != nick.to_lowercase()
                });
                buf.push_system(&msg);
            }
        }
        Event::Invited { channel, by } => {
            app.status_msg(&format!(
                "{by} invited you to {channel}. Type /join {channel}"
            ));
        }
        Event::TopicChanged {
            channel,
            topic,
            set_by,
        } => {
            let buf = app.buffer_mut(&channel);
            buf.topic = Some(topic.clone());
            match set_by {
                Some(who) => buf.push_system(&format!("{who} set topic: {topic}")),
                None => buf.push_system(&format!("Topic: {topic}")),
            }
        }
        Event::Names { channel, nicks } => {
            let buf = app.buffer_mut(&channel);
            // Accumulate nicks from multiple 353 replies (server may split across lines)
            // A new NAMES list starts fresh only when the first entry isn't already present
            if nicks.is_empty() {
                // Empty 353 — server sent no nicks (shouldn't happen, but handle gracefully)
            } else if buf.names_pending {
                // Continuation of an existing NAMES batch
                buf.nicks.extend(nicks.clone());
            } else {
                // Start of a new NAMES reply — replace
                buf.nicks = nicks.clone();
                buf.names_pending = true;
            }
        }
        Event::NamesEnd { channel } => {
            let buf = app.buffer_mut(&channel);
            buf.names_pending = false;
            buf.push_system(&format!("Users: {}", buf.nicks.join(", ")));
        }
        Event::UserQuit { nick, reason } => {
            // Remove from all channel nick lists and show quit message
            let buffers: Vec<String> = app.buffers.keys().cloned().collect();
            for buf_name in buffers {
                let buf = app.buffer_mut(&buf_name);
                let was_in = buf.nicks.iter().any(|n| {
                    let bare = n.trim_start_matches(['@', '+']);
                    bare == nick
                });
                if was_in {
                    buf.nicks.retain(|n| {
                        let bare = n.trim_start_matches(['@', '+']);
                        bare != nick
                    });
                    buf.push_system(&format!("{nick} has quit ({reason})"));
                }
            }
        }
        Event::ServerNotice { text } => {
            // Swallow the failure of a speculative "fetch history on view"
            // (maybe_fetch_history): a DM with a guest peer, or a not-yet-
            // persisted conversation, answers CHATHISTORY with INVALID_TARGET/
            // ACCOUNT_REQUIRED naming that same target. The user didn't ask
            // for history, so surfacing it as an error is just noise. A
            // user-initiated /msgs targets `*`, so its failure still shows.
            let is_speculative_history_fail = {
                let mut t = text.split_whitespace();
                t.next() == Some("CHATHISTORY")
                    && t.next().is_some() // error code
                    && t.next() == Some(app.active_buffer.as_str())
            };
            if is_speculative_history_fail {
                return;
            }
            // Show in the buffer the user is actually looking at — a FAIL (or
            // any server notice) responding to a command run from a channel/DM
            // was invisible when it only ever landed in the status buffer.
            let active = app.active_buffer.clone();
            app.buffer_mut(&active).push_system(&text);
            // Detect URLs in server notices and offer to open them
            if let Some(url) = extract_url(&text) {
                app.pending_url = Some(url.to_string());
                app.status_msg("Press Enter to open URL in browser, or any other key to dismiss.");
            }
        }
        Event::Disconnected { reason } => {
            app.connection_state = "disconnected".to_string();
            app.status_msg(&format!("Disconnected: {reason}"));
            // Don't quit — reconnection is handled by the main loop
            app.reconnect_pending = true;
        }
        Event::WhoisReply { nick: _, info } => {
            let buf = app.active_buffer.clone();
            app.buffer_mut(&buf).push_system(&format!("*** {info}"));

            // Fetch Bluesky profile on the "is authenticated as" line (has the DID).
            // We prefer using the DID since it's always present for authenticated users.
            // The handle line (671) comes after, but we don't need to fetch again.
            let actor = if info.contains("is authenticated as") {
                info.split_whitespace()
                    .find(|s| s.starts_with("did:"))
                    .map(|s| s.to_string())
            } else {
                None
            };

            if let Some(actor) = actor {
                let bg_tx = app.bg_result_tx.clone();
                let buf_clone = buf.clone();
                let avatar_cache = app.image_cache.clone();
                tokio::spawn(async move {
                    if let Ok(profile) = freeq_sdk::pds::fetch_profile(&actor).await {
                        let avatar_url = profile.avatar.clone();
                        if let Some(ref url) = avatar_url {
                            fetch_image_if_needed_direct(&avatar_cache, url);
                        }
                        let lines = profile.format_lines();
                        let _ = bg_tx
                            .send(crate::app::BgResult::ProfileLines(
                                buf_clone, lines, avatar_url,
                            ))
                            .await;
                    }
                });
            }
        }
        Event::AwayChanged { nick, away_msg } => {
            let msg = match &away_msg {
                Some(reason) => format!("{nick} is now away: {reason}"),
                None => format!("{nick} is no longer away"),
            };
            // Show in all shared buffers (channels where this nick might be)
            let buf_names: Vec<String> = app
                .buffers
                .keys()
                .filter(|name| *name != "status")
                .filter(|name| {
                    app.buffers
                        .get(*name)
                        .map(|b| {
                            b.nicks
                                .iter()
                                .any(|m| m.trim_start_matches(&['@', '+', '%'][..]) == nick)
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            for name in buf_names {
                app.buffer_mut(&name).push_system(&msg);
            }
        }
        Event::NickChanged { old_nick, new_nick } => {
            app.did_rename(&old_nick, &new_nick);
            let msg = format!("{old_nick} is now known as {new_nick}");
            for (name, buf) in app.buffers.iter_mut() {
                if name == "status" {
                    continue;
                }
                let mut updated = false;
                for n in &mut buf.nicks {
                    let bare = n.trim_start_matches(&['@', '+', '%'][..]);
                    if bare.eq_ignore_ascii_case(&old_nick) {
                        let prefix = n
                            .chars()
                            .next()
                            .filter(|c| *c == '@' || *c == '+' || *c == '%')
                            .map(|c| c.to_string())
                            .unwrap_or_default();
                        *n = format!("{prefix}{new_nick}");
                        updated = true;
                    }
                }
                if updated {
                    buf.push_system(&msg);
                }
            }
        }
        Event::ChatHistoryTarget {
            nick,
            timestamp,
            partner_did,
        } => {
            if let Some(ref did) = partner_did {
                app.record_member_did(&nick, did);
            }
            let ts_display = timestamp.as_deref().unwrap_or("?");
            app.buffer_mut("status")
                .push_system(&format!("  DM: {nick}  (last: {ts_display})"));
        }
        Event::RawLine(ref line) => {
            // Stash host part of the prefix on JOIN lines so we can surface
            // hostname cloaks (freeq/plc/xxx, freeq/guest) without changing
            // the SDK Event::Joined signature. RawLine is emitted before the
            // parsed event, so by the time Event::Joined fires the host is
            // already in nick_hosts.
            if let Some((nick, host)) = parse_join_prefix(line) {
                app.remember_nick_host(nick, &host);
            }
            if app.debug_raw {
                app.buffer_mut("status").push_system(&format!("← {line}"));
            }
        }
        Event::ReadMarker { target, timestamp } => {
            let ts = timestamp.as_deref().unwrap_or("*");
            app.status_msg(&format!("Read marker: {target} (up to {ts})"));
        }
    }
}

/// Whether a message carried a client signature, and the account the document
/// binds it to. An account tag alone proves nothing — the server states it —
/// so the two travel together; the marker needs both to mean anything.
fn signature_of(tags: &std::collections::HashMap<String, String>) -> (bool, Option<String>) {
    (
        tags.contains_key(freeq_sdk::sigtag::SIG_TAG),
        tags.get("account").cloned(),
    )
}

/// Where the connected server answers HTTP. Anything public is https on the
/// default port; a loopback server is a local build serving its web API in the
/// clear on the port it defaults to.
fn verify_api_base(server_addr: &str) -> String {
    let host = server_addr.rsplit_once(':').map_or(server_addr, |(h, _)| h);
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        format!("http://{host}:8080")
    } else {
        format!("https://{host}")
    }
}

/// Render the server's answer about one event as a line a person can read.
///
/// The verdict is three-way, and `verified_by` is the part that matters: a
/// message the sender's own device signed is a claim they cannot later
/// disown, while one the server signed is only the server vouching for what
/// it received. Collapsing those into "valid" would throw away the point of
/// client signing, so the line always says who vouches.
fn format_verify_verdict(body: &serde_json::Value) -> String {
    let Some(verification) = body.get("verification") else {
        return "Verify: the server returned no verdict for that id".to_string();
    };
    let verdict = verification
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let by = verification
        .get("verified_by")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let vouches = match by {
        "client-session-key" => "the sender's device signed it",
        "server-key" => "the server signed it, not the sender",
        "unsigned" => "nothing was signed",
        other => other,
    };

    // A mutation's id resolves to the act. There is no body to show, by
    // design: the log keeps facts about what was done, never content.
    if let Some(kind) = body.get("kind").and_then(|v| v.as_str()) {
        let subject = body
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        let emoji = body
            .get("emoji")
            .and_then(|v| v.as_str())
            .map(|e| format!(" {e}"))
            .unwrap_or_default();
        let actor = body
            .get("actor_did")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        return format!("Verify: {kind}{emoji} on {subject} by {actor} — {verdict} ({vouches})");
    }

    let signer = body
        .get("sender_did")
        .and_then(|v| v.as_str())
        .map(|d| format!(" by {d}"))
        .unwrap_or_default();
    format!("Verify: {verdict} ({vouches}){signer}")
}

/// Ask the connected server for its verdict on one event id.
async fn fetch_verdict(url: &str) -> Result<serde_json::Value> {
    let resp = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("server answered {status}");
    }
    Ok(resp.json().await?)
}

/// How long a first DM waits for the server to name its peer before going out
/// unsigned. A WHOIS round trip is milliseconds on a live connection; this is
/// the ceiling for the case where no answer is coming at all.
const DM_IDENTIFY_WAIT: Duration = Duration::from_secs(2);

/// Send a DM, holding the first one to a peer we cannot yet name.
///
/// A signature over a DM binds the pair of DIDs, so a peer known only by nick
/// has no venue any verifier could rebuild and the message goes out unsigned.
/// The server can answer who they are in one round trip, so a first DM waits
/// that long rather than losing its signature for the life of the session.
///
/// A peer with no DID — a guest — is the normal unsigned case: the wait
/// expires, the message goes to the bare nick, and we don't ask again.
/// Channels never wait; they are their own venue.
async fn send_dm(
    app: &mut App,
    handle: &client::ClientHandle,
    target: &str,
    text: &str,
) -> Result<()> {
    let is_channel = target.starts_with('#') || target.starts_with('&');
    if is_channel || handle.identified_dm_peer(target).is_some() {
        handle.privmsg(target, text).await?;
        return Ok(());
    }
    // Already waiting on this peer: queue behind it, or a later message
    // would overtake an earlier one on the wire.
    if app.dm_is_held(target) {
        app.hold_dm(target, text, Instant::now() + DM_IDENTIFY_WAIT);
        return Ok(());
    }
    if !app.first_dm_probe(target) {
        // We asked once and they have no DID to give. Don't ask again.
        handle.privmsg(target, text).await?;
        return Ok(());
    }
    handle.raw(&format!("WHOIS {target}")).await?;
    app.hold_dm(target, text, Instant::now() + DM_IDENTIFY_WAIT);
    Ok(())
}

/// Release DMs whose peer the server has now named, and those whose wait ran
/// out. Called every loop pass, so an answer landing this tick sends this tick.
async fn flush_pending_dms(app: &mut App, handle: &client::ClientHandle) {
    if app.pending_dms.is_empty() {
        return;
    }
    let ready = app.ready_dms(Instant::now(), |t| handle.identified_dm_peer(t).is_some());
    for (target, text) in ready {
        if let Err(e) = handle.privmsg(&target, &text).await {
            app.status_msg(&format!("Failed to send to {target}: {e}"));
        }
    }
}

async fn process_input(app: &mut App, handle: &client::ClientHandle, input: &str) -> Result<()> {
    if input.starts_with('/') {
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0].to_lowercase();
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd.as_str() {
            "/join" | "/j" => {
                if !arg.is_empty() {
                    handle.join(arg).await?;
                } else {
                    app.status_msg("Usage: /join #channel");
                }
            }
            "/part" | "/leave" => {
                let channel = if arg.is_empty() {
                    app.active_buffer.clone()
                } else {
                    arg.to_string()
                };
                if channel.starts_with('#') || channel.starts_with('&') {
                    handle.raw(&format!("PART {channel}")).await?;
                } else {
                    app.status_msg("Not in a channel");
                }
            }
            "/search" | "/find" => {
                let target = app.active_buffer.clone();
                if arg.trim().is_empty() {
                    app.status_msg("Usage: /search <text>");
                } else {
                    let needle = arg.trim().to_lowercase();
                    let matches: Vec<(String, String, String)> = app
                        .buffers
                        .get(&crate::app::buffer_key(&target))
                        .map(|buf| {
                            buf.messages
                                .iter()
                                .filter(|line| {
                                    !line.is_system
                                        && !line.is_deleted
                                        && line.text.to_lowercase().contains(&needle)
                                })
                                .rev()
                                .take(20)
                                .map(|line| {
                                    (line.timestamp.clone(), line.from.clone(), line.text.clone())
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    if matches.is_empty() {
                        app.status_msg(&format!("No matches for {:?}", arg.trim()));
                    } else {
                        app.status_msg(&format!(
                            "── {} match(es) for {:?} (newest first) ──",
                            matches.len(),
                            arg.trim()
                        ));
                        for (ts, from, text) in matches.iter().rev() {
                            let trimmed: String = text.chars().take(120).collect();
                            let ellipsis = if text.chars().count() > 120 {
                                "…"
                            } else {
                                ""
                            };
                            app.status_msg(&format!("  {ts} <{from}> {trimmed}{ellipsis}"));
                        }
                    }
                }
            }
            "/pin" => {
                let target = app.active_buffer.clone();
                if !target.starts_with('#') && !target.starts_with('&') {
                    app.status_msg("/pin only works in channels");
                } else {
                    let target_msgid = {
                        let buf = app.buffers.get(&crate::app::buffer_key(&target));
                        let trimmed = arg.trim();
                        if !trimmed.is_empty()
                            && buf.is_some_and(|b| b.find_by_msgid(trimmed).is_some())
                        {
                            Some(trimmed.to_string())
                        } else if trimmed.is_empty() {
                            buf.and_then(|b| b.recent_msgid()).map(|s| s.to_string())
                        } else {
                            None
                        }
                    };
                    match target_msgid {
                        None if !arg.trim().is_empty() => {
                            app.status_msg("Unknown msgid in this buffer")
                        }
                        None => app.status_msg("No message to pin in this buffer"),
                        Some(id) => {
                            handle.pin(&target, &id).await?;
                            // Server NOTICE will update the pin set on echo.
                        }
                    }
                }
            }
            "/unpin" => {
                let target = app.active_buffer.clone();
                if !target.starts_with('#') && !target.starts_with('&') {
                    app.status_msg("/unpin only works in channels");
                } else if arg.trim().is_empty() {
                    app.status_msg("Usage: /unpin <msgid>");
                } else {
                    handle.unpin(&target, arg.trim()).await?;
                }
            }
            "/pins" => {
                let target = app.active_buffer.clone();
                if !target.starts_with('#') && !target.starts_with('&') {
                    app.status_msg("/pins only works in channels");
                } else {
                    handle.raw(&format!("PINS {target}")).await?;
                }
            }
            "/reply" | "/re" => {
                let target = app.active_buffer.clone();
                if target == "status" {
                    app.status_msg("Not in a channel or DM");
                } else if arg.is_empty() {
                    app.status_msg("Usage: /reply [<msgid>] <text>");
                } else {
                    // Disambiguate "<msgid> <text>" vs "<text>" by checking
                    // whether the first token matches a known msgid.
                    let (target_msgid, reply_text) = {
                        let buf = app.buffers.get(&crate::app::buffer_key(&target));
                        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                        let first = parts[0];
                        let rest = parts.get(1).copied().unwrap_or("");
                        if !rest.is_empty() && buf.is_some_and(|b| b.find_by_msgid(first).is_some())
                        {
                            (Some(first.to_string()), rest.to_string())
                        } else {
                            let parent = buf.and_then(|b| b.recent_msgid()).map(|s| s.to_string());
                            (parent, arg.to_string())
                        }
                    };
                    match target_msgid {
                        None => app.status_msg("No message to reply to in this buffer"),
                        Some(id) => {
                            handle.reply(&target, &id, &reply_text).await?;
                            // echo-message returns the new line; the +reply tag
                            // populates reply_to so the indicator renders.
                        }
                    }
                }
            }
            "/verify" => {
                // Ask the server what it can prove about one event: a message
                // id, or the id of a delete or a reaction. The client checks
                // nothing itself — the point is the server's answer, which
                // anyone else can fetch and compare.
                let target = app.active_buffer.clone();
                let id = if arg.trim().is_empty() {
                    app.buffers
                        .get(&crate::app::buffer_key(&target))
                        .and_then(|b| b.recent_msgid())
                        .map(|s| s.to_string())
                } else {
                    Some(arg.trim().to_string())
                };
                match id.filter(|id| crate::app::is_valid_msgid(id)) {
                    None if !arg.trim().is_empty() => app.status_msg("Not a usable message id"),
                    None => app.status_msg("No message to verify in this buffer"),
                    Some(id) => {
                        let url =
                            format!("{}/api/v1/verify/{id}", verify_api_base(&app.server_addr));
                        let claimed = app
                            .buffers
                            .get(&crate::app::buffer_key(&target))
                            .and_then(|b| b.find_by_msgid(&id))
                            .and_then(|l| l.account.clone());
                        app.buffer_mut(&target)
                            .push_system(&format!("Verifying {id}..."));
                        let buf = target.clone();
                        let tx = app.bg_result_tx.clone();
                        tokio::spawn(async move {
                            let mut lines = match fetch_verdict(&url).await {
                                Ok(body) => vec![format_verify_verdict(&body)],
                                Err(e) => vec![format!("Verify failed: {e}")],
                            };
                            // The account the line claimed locally against the
                            // signer the server checked: they should agree, and
                            // a disagreement is exactly what verifying is for.
                            if let Some(claimed) = claimed {
                                lines.push(format!("  this client saw it as {claimed}"));
                            }
                            let _ = tx.send(crate::app::BgResult::VerifyLines(buf, lines)).await;
                        });
                    }
                }
            }
            "/edit" | "/e" => {
                let target = app.active_buffer.clone();
                if target == "status" {
                    app.status_msg("Not in a channel or DM");
                } else if arg.is_empty() {
                    app.status_msg("Usage: /edit [<msgid>] <new text>");
                } else {
                    // Two forms: "/edit <msgid> <text>" or "/edit <text>".
                    // Disambiguate by checking whether the first token matches
                    // a known msgid in the active buffer; if not, treat the
                    // whole arg as the new text targeting our most recent.
                    let (target_msgid, new_text) = {
                        let buf = app.buffers.get(&crate::app::buffer_key(&target));
                        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                        let first = parts[0];
                        let rest = parts.get(1).copied().unwrap_or("");
                        if !rest.is_empty() && buf.is_some_and(|b| b.find_by_msgid(first).is_some())
                        {
                            (Some(first.to_string()), rest.to_string())
                        } else {
                            let own = buf
                                .and_then(|b| b.recent_own_msgid(&app.nick))
                                .map(|s| s.to_string());
                            (own, arg.to_string())
                        }
                    };
                    match target_msgid {
                        None => app.status_msg("No own message to edit in this buffer"),
                        Some(id) => {
                            // Optimistic local apply — the echo runs apply_edit
                            // again with the same content, which is idempotent.
                            let nick = app.nick.clone();
                            app.apply_edit(&nick, None, &target, &id, None, &new_text);
                            handle.edit_message(&target, &id, &new_text).await?;
                        }
                    }
                }
            }
            "/delete" | "/del" => {
                let target = app.active_buffer.clone();
                if target == "status" {
                    app.status_msg("Not in a channel or DM");
                } else {
                    let target_msgid = {
                        let buf = app.buffers.get(&crate::app::buffer_key(&target));
                        let trimmed = arg.trim();
                        if !trimmed.is_empty()
                            && buf.is_some_and(|b| b.find_by_msgid(trimmed).is_some())
                        {
                            Some(trimmed.to_string())
                        } else if trimmed.is_empty() {
                            buf.and_then(|b| b.recent_own_msgid(&app.nick))
                                .map(|s| s.to_string())
                        } else {
                            None
                        }
                    };
                    match target_msgid {
                        None if !arg.trim().is_empty() => {
                            app.status_msg("Unknown msgid in this buffer")
                        }
                        None => app.status_msg("No own message to delete in this buffer"),
                        Some(id) => {
                            // Optimistic local apply — echo re-applies idempotently.
                            let nick = app.nick.clone();
                            app.apply_delete(&nick, None, &target, &id);
                            handle.delete_message(&target, &id).await?;
                        }
                    }
                }
            }
            "/react" | "/r" => {
                if arg.is_empty() {
                    app.status_msg("Usage: /react <emoji>");
                } else {
                    let target = app.active_buffer.clone();
                    if target != "status" {
                        let target_msgid = app
                            .buffers
                            .get(&crate::app::buffer_key(&target))
                            .and_then(|b| b.recent_msgid())
                            .map(|s| s.to_string());
                        if target_msgid.is_none() {
                            app.status_msg("No message to react to in this buffer");
                        } else {
                            let emoji = arg.trim().to_string();
                            // Record it locally as well as sending it: the
                            // echo re-adds the same entry idempotently, and
                            // without this `/unreact` couldn't find its own
                            // reaction on a server that never echoed.
                            if let Some(ref id) = target_msgid {
                                let nick = app.nick.clone();
                                app.buffer_mut(&target).add_reaction(id, &nick, &emoji);
                            }
                            let reaction = freeq_sdk::media::Reaction {
                                emoji,
                                msgid: target_msgid,
                            };
                            handle.send_reaction(&target, &reaction).await?;
                            // echo-message will deliver the reaction back to us
                        }
                    }
                }
            }
            "/unreact" | "/unr" => {
                if arg.is_empty() {
                    app.status_msg("Usage: /unreact <emoji>");
                } else {
                    let target = app.active_buffer.clone();
                    if target != "status" {
                        let emoji = arg.trim().to_string();
                        let nick = app.nick.clone();
                        let target_msgid = app
                            .buffers
                            .get(&crate::app::buffer_key(&target))
                            .and_then(|b| b.recent_reacted_msgid(&nick, &emoji))
                            .map(|s| s.to_string());
                        match target_msgid {
                            None => app.status_msg(&format!(
                                "No {emoji} reaction of yours in this buffer"
                            )),
                            Some(id) => {
                                // Optimistic — the echoed removal re-applies
                                // it, which the ledger treats as a no-op.
                                app.buffer_mut(&target).remove_reaction(&id, &nick, &emoji);
                                handle.unreact(&target, &emoji, &id).await?;
                            }
                        }
                    }
                }
            }
            "/preview" => {
                if arg.is_empty() {
                    app.status_msg("Usage: /preview <url>");
                } else {
                    let target = app.active_buffer.clone();
                    let url = arg.trim().to_string();
                    let handle_clone = handle.clone();
                    let buf = target.clone();
                    app.buffer_mut(&buf)
                        .push_system(&format!("Fetching preview for {url}..."));
                    tokio::spawn(async move {
                        match freeq_sdk::media::fetch_link_preview(&url).await {
                            Ok(preview) => {
                                let _ = handle_clone.send_link_preview(&buf, &preview).await;
                            }
                            Err(e) => {
                                tracing::warn!("Link preview failed for {url}: {e}");
                            }
                        }
                    });
                }
            }
            "/me" => {
                if !arg.is_empty() {
                    let target = app.active_buffer.clone();
                    if target != "status" {
                        let action = format!("\x01ACTION {arg}\x01");
                        handle.privmsg(&target, &action).await?;
                        // echo-message is negotiated; the server echoes our
                        // ACTION back as Event::Message which renders it via
                        // the CTCP branch. No optimistic local push, or we'd
                        // duplicate the line.
                    }
                }
            }
            "/msg" => {
                let msg_parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if msg_parts.len() == 2 {
                    send_dm(app, handle, msg_parts[0], msg_parts[1]).await?;
                } else {
                    app.status_msg("Usage: /msg <target> <message>");
                }
            }
            "/mode" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} {arg}")).await?;
                    } else {
                        app.status_msg("Usage: /mode <mode> [nick] (in a channel)");
                    }
                } else {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel}")).await?;
                    } else {
                        app.status_msg("Usage: /mode [+o|-o|+v|-v|+t|-t] [nick]");
                    }
                }
            }
            "/op" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} +o {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /op <nick>");
                }
            }
            "/deop" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} -o {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /deop <nick>");
                }
            }
            "/voice" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} +v {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /voice <nick>");
                }
            }
            "/ban" => {
                let channel = app.active_buffer.clone();
                if channel == "status" {
                    app.status_msg("Usage: /ban <mask|did> (in a channel)");
                } else if arg.is_empty() {
                    // List bans
                    handle.raw(&format!("MODE {channel} +b")).await?;
                } else {
                    handle.raw(&format!("MODE {channel} +b {arg}")).await?;
                }
            }
            "/unban" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} -b {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /unban <mask|did>");
                }
            }
            "/invite" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("INVITE {arg} {channel}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /invite <nick>");
                }
            }
            "/kick" | "/k" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        // /kick nick [reason]
                        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                        let target = parts[0];
                        let reason = parts.get(1).unwrap_or(&"Kicked");
                        handle
                            .raw(&format!("KICK {channel} {target} :{reason}"))
                            .await?;
                    }
                } else {
                    app.status_msg("Usage: /kick <nick> [reason]");
                }
            }
            "/topic" | "/t" => {
                if arg.is_empty() {
                    // Query topic
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("TOPIC {channel}")).await?;
                    } else {
                        app.status_msg("Usage: /topic [text] (in a channel)");
                    }
                } else {
                    // Set topic
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("TOPIC {channel} :{arg}")).await?;
                    } else {
                        app.status_msg("Usage: /topic [text] (in a channel)");
                    }
                }
            }
            "/whois" => {
                if !arg.is_empty() {
                    handle.raw(&format!("WHOIS {arg}")).await?;
                } else {
                    app.status_msg("Usage: /whois <nick>");
                }
            }
            "/media" | "/img" | "/upload" | "/crosspost" => {
                let cross_post = cmd == "/crosspost";
                if arg.is_empty() {
                    app.status_msg("Usage: /media <file path> [alt text]");
                    if cross_post {
                        app.status_msg("  /crosspost also shares to your Bluesky feed");
                    }
                } else {
                    let target = app.active_buffer.clone();
                    if target == "status" {
                        app.status_msg("Switch to a channel or PM first.");
                    } else {
                        // Parse: /media [--post] path [alt text]
                        // --post flag cross-posts to Bluesky feed
                        // Path can be quoted: /media "my file.jpg" alt text here
                        let (effective_arg, cross_post) =
                            if let Some(rest) = arg.strip_prefix("--post ") {
                                (rest, true)
                            } else {
                                (arg, cross_post)
                            };
                        let (path, alt) = if let Some(after_quote) = effective_arg.strip_prefix('"')
                        {
                            if let Some(end) = after_quote.find('"') {
                                let p = &after_quote[..end];
                                let rest = after_quote[end + 1..].trim();
                                (
                                    p.to_string(),
                                    if rest.is_empty() {
                                        None
                                    } else {
                                        Some(rest.to_string())
                                    },
                                )
                            } else {
                                (effective_arg.to_string(), None)
                            }
                        } else {
                            let parts: Vec<&str> = effective_arg.splitn(2, ' ').collect();
                            (parts[0].to_string(), parts.get(1).map(|s| s.to_string()))
                        };

                        upload_and_send_media(
                            app,
                            handle,
                            &target,
                            &path,
                            alt.as_deref(),
                            cross_post,
                        )
                        .await?;
                    }
                }
            }
            "/logout" => {
                // Clear cached OAuth session
                if app.authenticated_did.is_some() {
                    // Find handle from CLI args or use DID
                    let handle_hint = arg.trim();
                    if handle_hint.is_empty() {
                        app.status_msg("Usage: /logout <handle>");
                        app.status_msg("  Clears cached OAuth session for the given handle.");
                    } else {
                        let cache_path = freeq_sdk::oauth::default_session_path(handle_hint);
                        if cache_path.exists() {
                            let _ = std::fs::remove_file(&cache_path);
                            app.status_msg(&format!("Cleared cached session for {handle_hint}."));
                            app.status_msg("Reconnect to re-authenticate.");
                        } else {
                            app.status_msg(&format!("No cached session for {handle_hint}."));
                        }
                    }
                } else {
                    app.status_msg("Not authenticated.");
                }
            }
            "/quit" | "/q" => {
                handle
                    .quit(Some(if arg.is_empty() { "bye" } else { arg }))
                    .await?;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                app.should_quit = true;
            }
            "/raw" => {
                if !arg.is_empty() {
                    handle.raw(arg).await?;
                }
            }
            "/encrypt" | "/e2ee" => {
                let channel = app.active_buffer.clone();
                if channel == "status" {
                    app.status_msg("Switch to a channel first, then: /encrypt <passphrase>");
                } else if arg.is_empty() {
                    // Check if already encrypted
                    if app.channel_keys.contains_key(&channel) {
                        app.status_msg(&format!(
                            "🔒 Encryption is ON for {channel}. Use /decrypt to disable."
                        ));
                    } else {
                        app.status_msg("Usage: /encrypt <passphrase>");
                        app.status_msg("  Enables E2EE for this channel. All members need the same passphrase.");
                        app.status_msg("  Messages are encrypted client-side — the server only sees ciphertext.");
                    }
                } else {
                    let is_channel = channel.starts_with('#') || channel.starts_with('&');
                    // Channels salt by the shared channel name; DMs need a
                    // symmetric salt (canonical conversation key) so both
                    // peers derive the same key. Refuse a DM we can't key
                    // symmetrically rather than store a one-sided key that
                    // silently produces unreadable messages.
                    let salt = if is_channel {
                        Some(channel.clone())
                    } else {
                        app.dm_e2ee_salt(&channel)
                    };
                    match salt {
                        Some(salt) => {
                            let key = freeq_sdk::e2ee::derive_key(arg, &salt);
                            app.channel_keys.insert(channel.clone(), key);
                            app.buffer_mut(&channel).push_system(
                                "🔒 End-to-end encryption enabled. Messages here are now encrypted."
                            );
                            app.buffer_mut(&channel).push_system(
                                "   The other side must /encrypt with the same passphrase to read them.",
                            );
                            app.buffer_mut(&channel)
                                .push_system("   The server cannot read encrypted messages.");
                        }
                        None => {
                            app.buffer_mut(&channel).push_system(
                                "Can't enable E2EE here: this DM needs both sides DID-authenticated.",
                            );
                            app.buffer_mut(&channel).push_system(
                                "   Exchange a message first so the peer's identity is known, then retry.",
                            );
                        }
                    }
                }
            }
            "/decrypt" | "/noencrypt" => {
                let channel = app.active_buffer.clone();
                if app.channel_keys.remove(&channel).is_some() {
                    app.buffer_mut(&channel).push_system(
                        "🔓 Encryption disabled for this channel. Messages will be sent in plaintext."
                    );
                } else {
                    app.status_msg("Encryption is not enabled for this channel.");
                }
            }
            "/p2p" => {
                let p2p_parts: Vec<&str> = arg.splitn(3, ' ').collect();
                let subcmd = p2p_parts.first().copied().unwrap_or("");
                match subcmd {
                    "start" => {
                        if app.p2p_handle.is_some() {
                            app.status_msg("P2P already running.");
                        } else {
                            app.status_msg("Starting P2P endpoint...");
                            match freeq_sdk::p2p::start().await {
                                Ok((p2p_handle, rx)) => {
                                    app.status_msg(&format!(
                                        "✓ P2P ready! Your endpoint ID: {}",
                                        p2p_handle.endpoint_id
                                    ));
                                    app.p2p_handle = Some(p2p_handle);
                                    app.p2p_event_rx = Some(rx);
                                }
                                Err(e) => {
                                    app.status_msg(&format!("✗ P2P failed to start: {e}"));
                                }
                            }
                        }
                    }
                    "connect" if p2p_parts.len() >= 2 => {
                        if let Some(ref h) = app.p2p_handle {
                            let h = h.clone();
                            let peer_id = p2p_parts[1].to_string();
                            app.status_msg(&format!("Connecting to peer {}...", peer_id));
                            tokio::spawn(async move {
                                if let Err(e) = h.connect_peer(&peer_id).await {
                                    tracing::error!("P2P connect error: {e}");
                                }
                            });
                        } else {
                            app.status_msg("P2P not started. Use /p2p start first.");
                        }
                    }
                    "msg" if p2p_parts.len() >= 3 => {
                        if let Some(ref h) = app.p2p_handle {
                            let h = h.clone();
                            let peer_id = p2p_parts[1].to_string();
                            let text = p2p_parts[2].to_string();
                            let short = &peer_id[..8.min(peer_id.len())];
                            let buffer_key = format!("p2p:{short}");
                            let nick = app.nick.clone();
                            app.chat_msg(&buffer_key, &nick, &text);
                            tokio::spawn(async move {
                                if let Err(e) = h.send_message(&peer_id, &text).await {
                                    tracing::error!("P2P send error: {e}");
                                }
                            });
                        } else {
                            app.status_msg("P2P not started. Use /p2p start first.");
                        }
                    }
                    "id" => {
                        if let Some(ref h) = app.p2p_handle {
                            app.status_msg(&format!("Your P2P endpoint ID: {}", h.endpoint_id));
                        } else {
                            app.status_msg("P2P not started. Use /p2p start first.");
                        }
                    }
                    _ => {
                        app.status_msg("P2P commands:");
                        app.status_msg("  /p2p start              - Start P2P endpoint");
                        app.status_msg("  /p2p id                 - Show your endpoint ID");
                        app.status_msg("  /p2p connect <id>       - Connect to a peer");
                        app.status_msg("  /p2p msg <id> <message> - Send a direct message");
                    }
                }
            }
            "/net" | "/stats" => {
                app.show_net_popup = !app.show_net_popup;
            }
            "/debug" => {
                app.debug_raw = !app.debug_raw;
                let state = if app.debug_raw { "ON" } else { "OFF" };
                app.status_msg(&format!(
                    "Debug mode {state} — raw IRC lines will be shown in status buffer"
                ));
            }
            "/help" | "/h" | "/commands" => {
                app.status_msg("── Channel commands ─────────────────────");
                app.status_msg("  /join #channel      Join a channel (/j)");
                app.status_msg("  /part [#channel]    Leave a channel (/leave)");
                app.status_msg("  /topic [text]       View or set channel topic (/t)");
                app.status_msg("  /names              List users in current channel");
                app.status_msg("  /who #channel       Show who's in a channel");
                app.status_msg("  /list               List all channels");
                app.status_msg("  /history [N]        Fetch N messages of history (default 50)");
                app.status_msg("── Messaging ────────────────────────────");
                app.status_msg("  /msg target text    Private message");
                app.status_msg("  /msgs [N]           List DM conversations (default 50)");
                app.status_msg("  /me action          Action message (* nick does something)");
                app.status_msg("  /react emoji        React to most recent message (/r)");
                app.status_msg("  /unreact emoji      Take back that reaction (/unr)");
                app.status_msg(
                    "  /reply [id] text    Reply to most recent (or specific) message (/re)",
                );
                app.status_msg("  /edit [id] text     Edit your last (or a specific) message (/e)");
                app.status_msg(
                    "  /delete [id]        Delete your last (or a specific) message (/del)",
                );
                app.status_msg("  /pin [id]           Pin most recent (or specific) message");
                app.status_msg("  /unpin <id>         Unpin a message by msgid");
                app.status_msg("  /pins               List pinned messages in this channel");
                app.status_msg(
                    "  /verify [id]        Ask the server what it can prove about a message",
                );
                app.status_msg("  /search text        Search messages in current buffer (/find)");
                app.status_msg("  /preview url        Fetch and share a link preview");
                app.status_msg("── Channel moderation ───────────────────");
                app.status_msg("  /op nick            Give ops (@)");
                app.status_msg("  /deop nick          Remove ops");
                app.status_msg("  /voice nick         Give voice (+v)");
                app.status_msg("  /kick nick [why]    Kick user from channel (/k)");
                app.status_msg("  /ban [mask|did]     Ban a user (no args = list bans)");
                app.status_msg("  /unban mask|did     Remove a ban");
                app.status_msg("  /invite nick        Invite user to +i channel");
                app.status_msg("  /mode flags [arg]   Set channel modes:");
                app.status_msg("    +o/−o nick   ops     +v/−v nick   voice");
                app.status_msg("    +t/−t  topic lock    +i/−i  invite-only");
                app.status_msg("    +n/−n  no external   +m/−m  moderated");
                app.status_msg("    +k/−k key    channel key");
                app.status_msg("    +b/−b mask   ban");
                app.status_msg("── Identity & status ────────────────────");
                app.status_msg("  /nick newnick       Change your nick");
                app.status_msg("  /whois nick         Show user info + DID");
                app.status_msg("  /away [message]     Set/clear away status");
                app.status_msg("── Media & encryption ───────────────────");
                app.status_msg("  /media path [alt]   Upload and share a file (/img, /upload)");
                app.status_msg("  /crosspost path     Upload + cross-post to Bluesky");
                app.status_msg("  /encrypt passphrase Enable E2EE for this channel");
                app.status_msg("  /decrypt            Disable E2EE for this channel");
                app.status_msg("── Peer-to-peer ─────────────────────────");
                app.status_msg("  /p2p                Show P2P commands");
                app.status_msg("── Other ────────────────────────────────");
                app.status_msg("  /logout handle      Clear cached OAuth session");
                app.status_msg("  /net                Show/hide network info popup (/stats)");
                app.status_msg("  /debug              Toggle raw IRC line display");
                app.status_msg("  /reconnect          Force reconnect to server");
                app.status_msg("  /raw line           Send raw IRC command");
                app.status_msg("  /quit [message]     Disconnect (/q)");
                app.status_msg("── Navigation ───────────────────────────");
                app.status_msg("  /switch [name]    List or switch buffers (/sw)");
                app.status_msg("  /config           Show config + session state");
                app.status_msg("── Keys ─────────────────────────────────");
                app.status_msg("  Tab               Nick-complete (or next buffer if empty)");
                app.status_msg("  Shift-Tab         Previous buffer");
                app.status_msg("  Ctrl-N / Ctrl-P   Switch buffers");
                app.status_msg("  PageUp / PageDown Scroll messages");
                app.status_msg("  Ctrl-C / Ctrl-Q   Quit");
                app.status_msg("── Indicators ───────────────────────────");
                app.status_msg("  Tab bar shows (N) for unread, RED for mentions");
            }
            "/nick" => {
                if !arg.is_empty() {
                    handle.raw(&format!("NICK {arg}")).await?;
                } else {
                    app.status_msg("Usage: /nick <newnick>");
                }
            }
            "/away" => {
                if arg.is_empty() {
                    handle.raw("AWAY").await?;
                } else {
                    handle.raw(&format!("AWAY :{arg}")).await?;
                }
            }
            "/names" => {
                let channel = if arg.is_empty() {
                    app.active_buffer.clone()
                } else {
                    arg.to_string()
                };
                if channel.starts_with('#') || channel.starts_with('&') {
                    handle.raw(&format!("NAMES {channel}")).await?;
                } else {
                    app.status_msg("Usage: /names [#channel]");
                }
            }
            "/who" => {
                if !arg.is_empty() {
                    handle.raw(&format!("WHO {arg}")).await?;
                } else {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("WHO {channel}")).await?;
                    } else {
                        app.status_msg("Usage: /who <#channel|nick>");
                    }
                }
            }
            "/list" => {
                handle.raw("LIST").await?;
            }
            "/motd" => {
                handle.raw("MOTD").await?;
            }
            "/reconnect" => {
                app.status_msg("Forcing reconnect...");
                app.reconnect_pending = true;
                app.reconnect_delay = Duration::from_secs(0);
                app.reconnect_at = Some(std::time::Instant::now());
            }
            "/history" => {
                let channel = app.active_buffer.clone();
                if channel == "status" {
                    app.status_msg("Switch to a channel first.");
                } else {
                    let limit = if arg.is_empty() { "50" } else { arg };
                    handle
                        .raw(&format!("CHATHISTORY LATEST {channel} * {limit}"))
                        .await?;
                }
            }
            "/msgs" => {
                let limit = if arg.is_empty() { "50" } else { arg };
                app.status_msg("── DM conversations ────────────────────");
                handle
                    .chathistory_targets(limit.parse().unwrap_or(50))
                    .await?;
            }
            "/config" | "/settings" => {
                let cfg = config::Config::load();
                let session = config::Session::load();
                app.status_msg("── Config (~/.config/freeq/tui.toml) ────");
                app.status_msg(&format!(
                    "  server:  {}",
                    cfg.server
                        .as_deref()
                        .unwrap_or("(default: irc.freeq.at:6697)")
                ));
                app.status_msg(&format!(
                    "  nick:    {}",
                    cfg.nick.as_deref().unwrap_or("(auto)")
                ));
                app.status_msg(&format!(
                    "  handle:  {}",
                    cfg.handle.as_deref().unwrap_or("(none)")
                ));
                app.status_msg(&format!(
                    "  tls:     {}",
                    cfg.tls.map(|b| b.to_string()).unwrap_or("(auto)".into())
                ));
                app.status_msg(&format!("  vi:      {}", cfg.vi.unwrap_or(false)));
                let cfg_ch = cfg
                    .channels
                    .as_ref()
                    .map(|v| v.join(", "))
                    .unwrap_or("(none)".into());
                app.status_msg(&format!("  channels: {cfg_ch}"));
                app.status_msg("── Session (~/.config/freeq/session.toml) ─");
                app.status_msg(&format!(
                    "  last server:  {}",
                    session.server.as_deref().unwrap_or("(none)")
                ));
                app.status_msg(&format!(
                    "  last nick:    {}",
                    session.nick.as_deref().unwrap_or("(none)")
                ));
                let ses_ch = if session.channels.is_empty() {
                    "(none)".into()
                } else {
                    session.channels.join(", ")
                };
                app.status_msg(&format!("  channels:     {ses_ch}"));
                app.status_msg("  Tip: use --save-config to persist current CLI args");
                app.status_msg("  Tip: channels are auto-saved on quit");
            }
            "/switch" | "/sw" => {
                if arg.is_empty() {
                    // List all buffers with unread counts
                    let names = app.buffer_names();
                    app.status_msg("── Buffers ──────────────────────────────");
                    for name in &names {
                        let buf = app.buffers.get(name);
                        let unread = buf.map(|b| b.unread).unwrap_or(0);
                        let mention = buf.map(|b| b.has_mention).unwrap_or(false);
                        let marker = if name == &app.active_buffer {
                            " ← active"
                        } else if mention {
                            " ← MENTION"
                        } else if unread > 0 {
                            &format!(" ({unread} unread)")
                        } else {
                            ""
                        };
                        // DID-keyed DMs list as the peer's nick, with the
                        // compacted DID for disambiguation.
                        let label = if freeq_sdk::address::is_did(name) {
                            format!(
                                "{} [{}]",
                                app.display_name(name),
                                crate::app::shorten_did(name)
                            )
                        } else {
                            name.clone()
                        };
                        app.status_msg(&format!("  {label}{marker}"));
                    }
                    app.status_msg("  /switch <name> to switch");
                } else {
                    // Fuzzy match: find buffer whose key or display name
                    // contains the arg (DID-keyed DMs match by nick).
                    let target = arg.to_lowercase();
                    let names = app.buffer_names();
                    // Rank matches so an intent-revealing hit wins over
                    // BTreeMap order: a display-name/key that *starts with*
                    // the fragment beats one that merely contains it. Fixes
                    // `/sw didtest` landing on `#didtest` instead of the
                    // didtestbot DM.
                    let best = names
                        .iter()
                        .filter_map(|n| {
                            let key = n.to_lowercase();
                            let disp = app.display_name(n).to_lowercase();
                            let rank = if disp.starts_with(&target) || key.starts_with(&target) {
                                0
                            } else if disp.contains(&target) || key.contains(&target) {
                                1
                            } else {
                                return None;
                            };
                            Some((rank, n.clone()))
                        })
                        .min_by_key(|(rank, _)| *rank)
                        .map(|(_, n)| n);
                    if let Some(name) = best {
                        app.switch_to(&name);
                    } else if arg.starts_with('#') || arg.starts_with('&') {
                        // Channels have a distinct open step — /join. Don't
                        // conjure one from /switch.
                        app.status_msg(&format!("Not in {arg} — use /join to enter it"));
                    } else {
                        // A DM has no join: switching to it IS opening it.
                        // Key by the peer's DID when known so it lands on the
                        // persisted (DID-keyed) thread; history backfills via
                        // maybe_fetch_history once it's active.
                        let raw = arg.trim();
                        let key = if freeq_sdk::address::is_did(raw) {
                            raw.to_string()
                        } else {
                            app.did_for_nick(raw).unwrap_or_else(|| raw.to_string())
                        };
                        app.buffer_mut(&key);
                        app.switch_to(&key);
                    }
                }
            }
            _ => {
                // Pass unrecognized commands through to the server as raw IRC.
                // e.g. /policy #chan INFO → POLICY #chan INFO
                let raw_cmd = cmd.trim_start_matches('/').to_uppercase();
                let raw = if arg.is_empty() {
                    raw_cmd
                } else {
                    format!("{raw_cmd} {arg}")
                };
                handle.raw(&raw).await?;
            }
        }
    } else {
        let target = app.active_buffer.clone();
        if target == "status" {
            app.status_msg(
                "Cannot send messages to the status buffer. Use /msg or switch to a channel.",
            );
        } else {
            // Encrypt if E2EE is enabled for this channel
            let wire_text = if let Some(key) = app.channel_keys.get(&target) {
                match freeq_sdk::e2ee::encrypt(key, input) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        app.status_msg(&format!("Encryption failed: {e}"));
                        return Ok(());
                    }
                }
            } else {
                input.to_string()
            };
            send_dm(app, handle, &target, &wire_text).await?;
            // echo-message cap is negotiated, so server will echo it back.
            // Don't add locally — that would duplicate the message.
        }
    }

    Ok(())
}

/// Upload a file to PDS and send as a tagged media message.
async fn upload_and_send_media(
    app: &mut App,
    handle: &client::ClientHandle,
    target: &str,
    path: &str,
    alt: Option<&str>,
    cross_post: bool,
) -> Result<()> {
    let uploader = match &app.media_uploader {
        Some(u) => u.clone(),
        None => {
            let msg = "Media upload requires Bluesky authentication (--handle)";
            app.buffer_mut(&app.active_buffer.clone()).push_system(msg);
            return Ok(());
        }
    };

    // Expand ~ in path
    let path: std::path::PathBuf = if path.starts_with("~/") {
        dirs::home_dir()
            .map(|h: std::path::PathBuf| h.join(&path[2..]))
            .unwrap_or_else(|| std::path::PathBuf::from(path))
    } else {
        std::path::PathBuf::from(path)
    };

    if !path.exists() {
        let msg = format!("File not found: {}", path.display());
        app.buffer_mut(&app.active_buffer.clone()).push_system(&msg);
        return Ok(());
    }

    let data = std::fs::read(&path)?;
    let filename = path
        .file_name()
        .and_then(|n: &std::ffi::OsStr| n.to_str())
        .unwrap_or("file");

    // Guess content type from extension
    let content_type = match path
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .unwrap_or("")
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    };

    let buf_name = app.active_buffer.clone();
    app.buffer_mut(&buf_name).push_system(&format!(
        "Uploading {filename} ({})...",
        format_file_size(data.len() as u64)
    ));

    // Channel name for the record (if target is a channel)
    let channel = if target.starts_with('#') {
        Some(target)
    } else {
        None
    };

    match freeq_sdk::media::upload_media_to_pds(
        &uploader.pds_url,
        &uploader.did,
        &uploader.access_token,
        uploader.dpop_key.as_ref(),
        uploader.dpop_nonce.as_deref(),
        content_type,
        &data,
        alt,
        channel,
        cross_post,
    )
    .await
    {
        Ok(result) => {
            let media = freeq_sdk::media::MediaAttachment {
                content_type: content_type.to_string(),
                url: result.url.clone(),
                alt: alt.map(|s| s.to_string()),
                width: None,
                height: None,
                blurhash: None,
                size: Some(result.size),
                filename: Some(filename.to_string()),
            };

            handle.send_media(target, &media).await?;

            // Show in our own buffer
            let _display = format_media_display(&media);
            let img_url = if media.content_type.starts_with("image/") {
                Some(media.url.clone())
            } else {
                None
            };
            if let Some(ref url) = img_url {
                fetch_image_if_needed(&app.image_cache, url);
            }
            // No optimistic local push — echo-message will deliver the
            // media message back through Event::Message which renders it
            // via the media branch. Avoid the duplicate that resulted from
            // pushing locally and then receiving the echo.

            let suffix = if cross_post {
                " (also posted to Bluesky)"
            } else {
                ""
            };
            app.buffer_mut(&buf_name)
                .push_system(&format!("Shared {filename}{suffix}"));
        }
        Err(e) => {
            app.buffer_mut(&buf_name)
                .push_system(&format!("Upload failed: {e}"));
        }
    }

    Ok(())
}

/// Same as fetch_image_if_needed but callable from async contexts with a cloned cache.
fn fetch_image_if_needed_direct(cache: &crate::app::ImageCache, url: &str) {
    fetch_image_if_needed(cache, url);
}

/// Kick off a background fetch for an image URL if not already cached.
fn fetch_image_if_needed(cache: &crate::app::ImageCache, url: &str) {
    // Only fetch from https and known hosts
    if !url.starts_with("https://") {
        return;
    }
    // Extract host from URL for allowlist check
    let host = url
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())
        .unwrap_or("");
    let allowed = host.ends_with(".bsky.network")
        || host == "cdn.bsky.app"
        || host.ends_with(".bsky.app")
        || host.ends_with("freeq.at");
    if !allowed {
        return;
    }

    let mut guard = cache.lock().unwrap();
    if guard.contains_key(url) {
        return;
    }
    guard.insert(url.to_string(), crate::app::ImageState::Loading);
    drop(guard);

    // Evict old entries before adding new ones
    crate::app::evict_image_cache(cache);

    let cache = cache.clone();
    let url = url.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        match client.get(&url).send().await {
            Ok(resp) => {
                // Check content-length before downloading
                if let Some(len) = resp.content_length()
                    && len > crate::app::MAX_IMAGE_BYTES as u64
                {
                    cache
                        .lock()
                        .unwrap()
                        .insert(url, crate::app::ImageState::Failed("Too large".into()));
                    return;
                }
                match resp.bytes().await {
                    Ok(bytes) if bytes.len() <= crate::app::MAX_IMAGE_BYTES => {
                        match image::load_from_memory(&bytes) {
                            Ok(img) => {
                                // Downscale large images to save memory
                                let img = if img.width() > 800 || img.height() > 600 {
                                    img.thumbnail(800, 600)
                                } else {
                                    img
                                };
                                cache
                                    .lock()
                                    .unwrap()
                                    .insert(url, crate::app::ImageState::Ready(img));
                            }
                            Err(e) => {
                                cache
                                    .lock()
                                    .unwrap()
                                    .insert(url, crate::app::ImageState::Failed(e.to_string()));
                            }
                        }
                    }
                    Ok(_) => {
                        cache
                            .lock()
                            .unwrap()
                            .insert(url, crate::app::ImageState::Failed("Too large".into()));
                    }
                    Err(e) => {
                        cache
                            .lock()
                            .unwrap()
                            .insert(url, crate::app::ImageState::Failed(e.to_string()));
                    }
                }
            }
            Err(e) => {
                cache
                    .lock()
                    .unwrap()
                    .insert(url, crate::app::ImageState::Failed(e.to_string()));
            }
        }
    });
}

/// Format a media attachment for display in the TUI.
/// Pull (nick, host) from an IRC line whose command is JOIN.
/// Skips IRCv3 message tags (leading `@...`) and matches lines like
/// `:nick!user@host JOIN #channel ...`. Returns None for non-JOIN
/// lines or lines we can't parse.
fn parse_join_prefix(line: &str) -> Option<(&str, String)> {
    let mut rest = line;
    if let Some(stripped) = rest.strip_prefix('@') {
        // Skip the tags block up to the first space.
        let space = stripped.find(' ')?;
        rest = &stripped[space + 1..];
    }
    let prefix = rest.strip_prefix(':')?;
    let space = prefix.find(' ')?;
    let (source, after) = (&prefix[..space], &prefix[space + 1..]);
    // `after` should start with the command. Confirm it's JOIN.
    let cmd = after.split_ascii_whitespace().next()?;
    if !cmd.eq_ignore_ascii_case("JOIN") {
        return None;
    }
    let bang = source.find('!')?;
    let nick = &source[..bang];
    let at = source[bang + 1..].find('@')?;
    let host = &source[bang + 1 + at + 1..];
    // IRC convention bounds nicks to 30 chars and hostnames to 64 (RFC
    // 2812 §1.3). We allow generous headroom to account for cloak
    // formats but still reject pathological inputs that would let a
    // hostile peer eat memory in our nick_hosts cache.
    const MAX_NICK_LEN: usize = 64;
    const MAX_HOST_LEN: usize = 256;
    if nick.is_empty() || nick.len() > MAX_NICK_LEN {
        return None;
    }
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return None;
    }
    // Reject control characters in either component. They have no business
    // appearing in a real prefix, and rendering them would let a hostile
    // peer move the terminal cursor through our system messages.
    let bad = |s: &str| s.chars().any(|c| c.is_control());
    if bad(nick) || bad(host) {
        return None;
    }
    Some((nick, host.to_string()))
}

fn format_timestamp(tags: &std::collections::HashMap<String, String>) -> String {
    if let Some(ts) = tags.get("time")
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts)
    {
        return dt
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string();
    }
    chrono::Local::now().format("%H:%M:%S").to_string()
}

fn parse_timestamp_ms(tags: &std::collections::HashMap<String, String>) -> i64 {
    if let Some(ts) = tags.get("time")
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts)
    {
        return dt.timestamp_millis();
    }
    chrono::Local::now().timestamp_millis()
}

/// When a channel or DM buffer becomes active, request `CHATHISTORY LATEST`
/// once — the same "fetch history on view" the web client does. Channels
/// only receive a server-side history push on a *fresh* JOIN; a multi-device
/// attach (a second session of a DID already in the channel) gets JOIN/NAMES
/// but no history push, so without this an attaching device is blank. The
/// batch flush dedups by msgid, so overlap with a fresh-join push is
/// harmless. No-op for status/P2P buffers and anything already requested.
///
/// Guests skip *DM* history: guest DMs aren't persisted (both sides need a
/// DID), so the request has nothing to return and the server rejects it with
/// ACCOUNT_REQUIRED — which would then surface as an error in the DM window.
/// Channel history is fine for guests.
async fn maybe_fetch_history(app: &mut crate::app::App, handle: &client::ClientHandle) {
    let key = app.active_buffer.clone();
    let is_channel = key.starts_with('#') || key.starts_with('&');
    let eligible = key != "status"
        && !key.starts_with("p2p:")
        && app.buffers.contains_key(&key)
        && (is_channel || app.authenticated_did.is_some());
    if !eligible || app.history_requested.contains(&key) {
        return;
    }
    app.history_requested.insert(key.clone());
    let _ = handle.raw(&format!("CHATHISTORY LATEST {key} * 50")).await;
}

fn push_line_to_buffer(
    app: &mut crate::app::App,
    batch_id: Option<&String>,
    buf_name: &str,
    timestamp_ms: i64,
    line: crate::app::BufferLine,
) {
    if let Some(id) = batch_id
        && app.batches.contains_key(id)
    {
        app.add_batch_line(id, timestamp_ms, line);
        return;
    }
    app.buffer_mut(buf_name).push(line);
}

fn format_link_preview(preview: &freeq_sdk::media::LinkPreview) -> String {
    let mut parts = vec!["🔗".to_string()];
    if let Some(ref title) = preview.title {
        parts.push(title.clone());
    }
    if let Some(ref desc) = preview.description {
        // Truncate long descriptions
        let short = if desc.len() > 120 {
            format!("{}…", &desc[..120])
        } else {
            desc.clone()
        };
        parts.push(format!("— {short}"));
    }
    parts.push(format!("({})", preview.url));
    parts.join(" ")
}

/// Extract the first http/https URL from a message.
fn extract_url(text: &str) -> Option<String> {
    for word in text.split_whitespace() {
        if (word.starts_with("https://") || word.starts_with("http://"))
            && word.len() > 10
            // Don't preview our own CDN/PDS URLs
            && !word.contains("cdn.bsky.app")
            && !word.contains("/xrpc/")
        {
            // Strip trailing punctuation
            let url = word.trim_end_matches(['.', ',', ')', ']', ';']);
            return Some(url.to_string());
        }
    }
    None
}

fn format_media_display(media: &freeq_sdk::media::MediaAttachment) -> String {
    let type_icon = if media.is_image() {
        "🖼"
    } else if media.is_video() {
        "🎬"
    } else if media.is_audio() {
        "🎵"
    } else {
        "📎"
    };

    let mut parts = vec![format!("{type_icon} [{ct}]", ct = media.content_type)];

    if let Some(ref alt) = media.alt {
        parts.push(alt.clone());
    }

    if let (Some(w), Some(h)) = (media.width, media.height) {
        parts.push(format!("{w}×{h}"));
    }

    if let Some(size) = media.size {
        parts.push(format_file_size(size));
    }

    parts.push(media.url.clone());
    parts.join(" ")
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn try_nick_complete(app: &mut App) {
    let cursor = app.editor.cursor;
    let text = &app.editor.text;

    // Find the word fragment before the cursor
    let before_cursor = &text[..cursor];
    let word_start = before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
    let fragment = &before_cursor[word_start..];
    if fragment.is_empty() {
        return;
    }

    let fragment_lower = fragment.to_lowercase();

    // Get nicks from the current buffer
    let nicks = match app.buffers.get(&app.active_buffer) {
        Some(buf) => &buf.nicks,
        None => return,
    };

    // Find first matching nick (strip @ and + prefixes for comparison)
    let matching = nicks.iter().find_map(|n| {
        let bare = n.trim_start_matches(['@', '+']);
        if bare.to_lowercase().starts_with(&fragment_lower) {
            Some(bare.to_string())
        } else {
            None
        }
    });

    if let Some(completion) = matching {
        let suffix = if word_start == 0 { ": " } else { " " };
        let after = &text[cursor..];
        let new_text = format!("{}{}{}{}", &text[..word_start], completion, suffix, after,);
        let new_cursor = word_start + completion.len() + suffix.len();
        app.editor.text = new_text;
        app.editor.cursor = new_cursor;
    }
}

#[cfg(test)]
mod tests {
    use super::parse_join_prefix;
    use super::{format_verify_verdict, signature_of, verify_api_base};
    use std::collections::HashMap;

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_signed_message_carries_its_signature_and_the_account_it_binds() {
        let (signed, account) = signature_of(&tags(&[
            ("+freeq.at/sig", "ed25519:kid:c2ln"),
            ("account", "did:plc:alice"),
            ("msgid", "01ABC"),
        ]));
        assert!(signed);
        assert_eq!(account.as_deref(), Some("did:plc:alice"));
    }

    #[test]
    fn an_unsigned_message_claims_nothing() {
        let (signed, account) = signature_of(&tags(&[("account", "did:plc:alice")]));
        assert!(!signed, "an account tag is not a signature");
        assert_eq!(account.as_deref(), Some("did:plc:alice"));

        let (signed, account) = signature_of(&tags(&[]));
        assert!(!signed);
        assert_eq!(account, None);
    }

    #[test]
    fn the_verify_endpoint_lives_on_the_server_we_are_connected_to() {
        assert_eq!(
            verify_api_base("irc.zerosum.org:6697"),
            "https://irc.zerosum.org"
        );
        assert_eq!(verify_api_base("irc.freeq.at"), "https://irc.freeq.at");
        // A local server serves its web API on the port it defaults to,
        // in the clear — a self-signed https guess would just fail.
        assert_eq!(verify_api_base("127.0.0.1:6667"), "http://127.0.0.1:8080");
        assert_eq!(verify_api_base("localhost:6667"), "http://localhost:8080");
    }

    #[test]
    fn a_verdict_reads_as_who_vouches_for_the_message() {
        // The pass condition: the sender's own device signed it.
        let v = format_verify_verdict(&serde_json::json!({
            "verification": { "verdict": "valid", "verified_by": "client-session-key" },
            "sender_did": "did:plc:alice",
        }));
        assert!(v.contains("valid"), "{v}");
        assert!(v.contains("the sender's device"), "{v}");

        // A server-signed message is honest but weaker — the server vouches,
        // not the sender, and the reader has to be able to tell.
        let v = format_verify_verdict(&serde_json::json!({
            "verification": { "verdict": "valid", "verified_by": "server-key" },
        }));
        assert!(v.contains("valid"), "{v}");
        assert!(v.contains("the server"), "{v}");

        // Nothing to check, and a signature that fails: distinct states.
        let v = format_verify_verdict(&serde_json::json!({
            "verification": { "verdict": "unverifiable", "verified_by": "unsigned" },
        }));
        assert!(v.contains("unverifiable"), "{v}");
        let v = format_verify_verdict(&serde_json::json!({
            "verification": { "verdict": "invalid", "verified_by": "client-session-key" },
        }));
        assert!(v.contains("invalid"), "{v}");
    }

    #[test]
    fn a_mutations_verdict_names_the_act_it_covers() {
        // A reaction's event id resolves to the act, not to a message body.
        let v = format_verify_verdict(&serde_json::json!({
            "kind": "unreact",
            "actor_did": "did:plc:alice",
            "subject": "01ROOT",
            "emoji": "👍",
            "verification": { "verdict": "valid", "verified_by": "client-session-key" },
        }));
        assert!(v.contains("unreact"), "{v}");
        assert!(v.contains("01ROOT"), "{v}");
        assert!(v.contains("👍"), "{v}");
        assert!(v.contains("valid"), "{v}");
    }

    #[test]
    fn a_verdict_the_server_did_not_send_is_not_invented() {
        let v = format_verify_verdict(&serde_json::json!({ "msgid": "01ABC" }));
        assert!(
            v.contains("no verdict"),
            "a missing verification block must read as missing, got: {v}"
        );
    }

    #[test]
    fn parse_join_prefix_basic() {
        let line = ":alice!~u@freeq/plc/abc123 JOIN #freeq";
        let (nick, host) = parse_join_prefix(line).expect("matches");
        assert_eq!(nick, "alice");
        assert_eq!(host, "freeq/plc/abc123");
    }

    #[test]
    fn parse_join_prefix_with_tags() {
        let line = "@account=alice;time=2026-05-13T12:00:00.000Z :alice!~u@freeq/guest JOIN #room";
        let (nick, host) = parse_join_prefix(line).expect("matches");
        assert_eq!(nick, "alice");
        assert_eq!(host, "freeq/guest");
    }

    #[test]
    fn parse_join_prefix_with_extended_join_params() {
        // Extended-join adds account + realname as params; prefix is unchanged.
        let line = ":alice!~u@freeq/plc/xyz JOIN #room account :Alice Doe";
        let (nick, host) = parse_join_prefix(line).expect("matches");
        assert_eq!(nick, "alice");
        assert_eq!(host, "freeq/plc/xyz");
    }

    #[test]
    fn parse_join_prefix_rejects_non_join() {
        let line = ":alice!~u@host PRIVMSG #room :hi";
        assert!(parse_join_prefix(line).is_none());
    }

    #[test]
    fn parse_join_prefix_rejects_serverless_prefix() {
        let line = "PING :keepalive";
        assert!(parse_join_prefix(line).is_none());
    }

    #[test]
    fn parse_join_prefix_rejects_malformed_prefix() {
        // No `!` ⇒ can't extract nick.
        let line = ":alice JOIN #room";
        assert!(parse_join_prefix(line).is_none());
    }

    /// SECURITY: a server (or wire injector) might emit a JOIN whose host
    /// part contains control characters. Those would land in nick_hosts
    /// and be rendered into the system message ("alice […] has joined")
    /// where they could move the cursor or repaint the screen. Reject any
    /// host that contains control characters (specifically CR/LF, NUL,
    /// or ESC).
    #[test]
    fn parse_join_prefix_rejects_control_chars_in_host() {
        let cases = [
            ":alice!~u@freeq/plc/abc\r JOIN #room",
            ":alice!~u@freeq/plc/abc\n JOIN #room",
            ":alice!~u@\x00evil JOIN #room",
            ":alice!~u@\x1b[31mEVIL JOIN #room",
        ];
        for line in cases {
            assert!(
                parse_join_prefix(line).is_none(),
                "must reject control-char host: {line:?}"
            );
        }
    }

    /// SECURITY: same hardening applied to the nick component — a
    /// crafted prefix with control chars in the nick must be rejected.
    #[test]
    fn parse_join_prefix_rejects_control_chars_in_nick() {
        let line = ":alice\x07!~u@freeq/plc/abc JOIN #room";
        assert!(parse_join_prefix(line).is_none());
    }

    /// DoS: an unbounded JOIN prefix lets a hostile peer push huge
    /// strings into our `nick_hosts` map (where the cap helps but each
    /// stored entry is still O(prefix-size) bytes). Reject anything
    /// where the nick or host part is longer than IRC convention.
    #[test]
    fn parse_join_prefix_rejects_giant_components() {
        let huge_host = "a".repeat(8192);
        let line = format!(":alice!~u@{huge_host} JOIN #room");
        assert!(
            parse_join_prefix(&line).is_none(),
            "must reject host longer than reasonable bound"
        );

        let huge_nick = "n".repeat(8192);
        let line = format!(":{huge_nick}!~u@freeq/plc/abc JOIN #room");
        assert!(parse_join_prefix(&line).is_none(), "must reject giant nick");
    }
}
