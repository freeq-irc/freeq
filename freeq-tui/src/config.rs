//! Persistent configuration for freeq-tui.
//!
//! Config file lives at `~/.config/freeq/tui.toml`.
//! Session state (last server, channels) at `~/.config/freeq/session.toml`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default IRC server.
pub const DEFAULT_SERVER: &str = "irc.freeq.at:6697";
/// Default channel to join on first run.
pub const DEFAULT_CHANNEL: &str = "#freeq";

/// User configuration (persisted in tui.toml).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Server address (host:port). Default: irc.freeq.at:6697
    pub server: Option<String>,
    /// IRC nickname.
    pub nick: Option<String>,
    /// Bluesky handle for OAuth login.
    pub handle: Option<String>,
    /// Use TLS (auto-detected from :6697, but can force).
    pub tls: Option<bool>,
    /// Skip TLS certificate verification.
    pub tls_insecure: Option<bool>,
    /// Use vi keybindings.
    pub vi: Option<bool>,
    /// Channels to auto-join (overrides session state).
    pub channels: Option<Vec<String>>,
    /// Iroh endpoint address (P2P transport).
    pub iroh_addr: Option<String>,
    /// Join/part/quit lines: "hidden" (default), "grouped" or "all".
    pub join_part: Option<crate::presence::JoinPartDisplay>,
}

/// Session state saved on quit, restored on start.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Session {
    /// Last server connected to.
    pub server: Option<String>,
    /// Last nick used.
    pub nick: Option<String>,
    /// Last handle used for auth.
    pub handle: Option<String>,
    /// Channels that were open on quit.
    pub channels: Vec<String>,
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("freeq")
}

fn config_path() -> PathBuf {
    config_dir().join("tui.toml")
}

fn session_path() -> PathBuf {
    config_dir().join("session.toml")
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(s) => match toml::from_str(&s) {
                    Ok(c) => return c,
                    Err(e) => eprintln!("Warning: bad config file {}: {e}", path.display()),
                },
                Err(e) => eprintln!("Warning: can't read {}: {e}", path.display()),
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = config_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match toml::to_string_pretty(self) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&path, s) {
                    eprintln!("Warning: can't save config: {e}");
                }
            }
            Err(e) => eprintln!("Warning: can't serialize config: {e}"),
        }
    }
}

impl Session {
    pub fn load() -> Self {
        let path = session_path();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(s) => match toml::from_str(&s) {
                    Ok(c) => return c,
                    Err(e) => eprintln!("Warning: bad session file {}: {e}", path.display()),
                },
                Err(e) => eprintln!("Warning: can't read {}: {e}", path.display()),
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = session_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match toml::to_string_pretty(self) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&path, s) {
                    eprintln!("Warning: can't save session: {e}");
                }
            }
            Err(e) => eprintln!("Warning: can't serialize session: {e}"),
        }
    }
}

/// Resolve the effective values by merging CLI args > config file > session state > defaults.
pub struct Resolved {
    pub server: String,
    pub nick: String,
    pub handle: Option<String>,
    pub tls: bool,
    pub tls_insecure: bool,
    pub vi: bool,
    pub channels: Vec<String>,
    pub iroh_addr: Option<String>,
}

impl Resolved {
    /// Merge: CLI overrides > config file > session state > defaults.
    pub fn merge(cli: &super::Cli, config: &Config, session: &Session) -> Self {
        let server = cli
            .server
            .clone()
            .or_else(|| config.server.clone())
            .or_else(|| session.server.clone())
            .unwrap_or_else(|| DEFAULT_SERVER.to_string());

        // Ensure server has a port; default to 6697 (TLS) if missing
        let server = if server.contains(':') {
            server
        } else {
            format!("{server}:6697")
        };

        let handle = cli
            .handle
            .clone()
            .or_else(|| config.handle.clone())
            .or_else(|| session.handle.clone())
            .or_else(cached_oauth_handle);

        let nick = cli
            .nick
            .clone()
            .or_else(|| config.nick.clone())
            .or_else(|| session.nick.clone())
            .unwrap_or_else(|| {
                // Derive from handle or system username
                handle
                    .as_ref()
                    .map(|h| h.split('.').next().unwrap_or("guest").to_string())
                    .unwrap_or_else(|| {
                        whoami::fallible::username().unwrap_or_else(|_| "guest".to_string())
                    })
            });

        let tls_explicit = cli.tls || config.tls.unwrap_or(false);
        let tls = tls_explicit || server.ends_with(":6697");

        let tls_insecure = cli.tls_insecure || config.tls_insecure.unwrap_or(false);
        let vi = cli.vi || config.vi.unwrap_or(false);

        // Channels: CLI > config > session > default
        let channels = if let Some(ref ch) = cli.channels {
            ch.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else if let Some(ref ch) = config.channels {
            ch.clone()
        } else if !session.channels.is_empty() {
            session.channels.clone()
        } else {
            vec![DEFAULT_CHANNEL.to_string()]
        };

        let iroh_addr = cli.iroh_addr.clone().or_else(|| config.iroh_addr.clone());

        Self {
            server,
            nick,
            handle,
            tls,
            tls_insecure,
            vi,
            channels,
            iroh_addr,
        }
    }
}

/// Returns true if the user passed any explicit CLI flags that indicate
/// they want to skip the interactive setup form.
pub fn has_explicit_cli_args(cli: &super::Cli) -> bool {
    cli.server.is_some()
        || cli.nick.is_some()
        || cli.handle.is_some()
        || cli.did.is_some()
        || cli.app_password.is_some()
        || cli.gen_key
        || cli.iroh_addr.is_some()
        || cli.channels.is_some()
        || cli.send.is_some()
}

/// Returns true if we have a saved session with a handle (can auto-reconnect).
pub fn has_saved_session(config: &Config, session: &Session) -> bool {
    config.handle.is_some() || session.handle.is_some() || cached_oauth_handle().is_some()
}

/// Check for a cached OAuth session file (e.g. `chadfowler.com.session.json`)
/// and return the handle if found.
pub fn cached_oauth_handle() -> Option<String> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("freeq-tui");
    if !dir.exists() {
        return None;
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".session.json"))
        .collect();
    // Sort by modification time (most recent first) so we pick the latest session
    entries.sort_by(|a, b| {
        let t_a = a
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let t_b = b
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        t_b.cmp(&t_a)
    });
    entries
        .first()
        .map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".session.json")
                .unwrap_or("")
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// Show interactive setup form on stderr. Returns a Resolved.
/// This runs before the TUI starts (plain terminal I/O).
pub fn interactive_setup(config: &Config, session: &Session) -> Option<Resolved> {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stderr();

    // Banner
    writeln!(stdout).ok();
    writeln!(stdout, "  ╭─────────────────────────────────────────╮").ok();
    writeln!(
        stdout,
        "  │           \x1b[1;36mfreeq\x1b[0m — decentralized chat       │"
    )
    .ok();
    writeln!(stdout, "  │     with cryptographic identity          │").ok();
    writeln!(stdout, "  ╰─────────────────────────────────────────╯").ok();
    writeln!(stdout).ok();
    writeln!(
        stdout,
        "  \x1b[90mSign in with Bluesky for verified identity,\x1b[0m"
    )
    .ok();
    writeln!(
        stdout,
        "  \x1b[90mor press Enter to connect as a guest.\x1b[0m"
    )
    .ok();
    writeln!(stdout).ok();

    // Bluesky handle
    let saved_handle = config
        .handle
        .as_deref()
        .or(session.handle.as_deref())
        .unwrap_or("");
    if saved_handle.is_empty() {
        write!(
            stdout,
            "  \x1b[1mBluesky handle\x1b[0m (e.g. alice.bsky.social): "
        )
        .ok();
    } else {
        write!(stdout, "  \x1b[1mBluesky handle\x1b[0m [{saved_handle}]: ").ok();
    }
    stdout.flush().ok();
    let mut handle_input = String::new();
    stdin.lock().read_line(&mut handle_input).ok();
    let handle_input = handle_input.trim().to_string();
    let handle = if handle_input.is_empty() {
        if saved_handle.is_empty() {
            None
        } else {
            Some(saved_handle.to_string())
        }
    } else {
        Some(handle_input)
    };

    // Nick (derive from handle)
    let default_nick = handle
        .as_ref()
        .map(|h| h.split('.').next().unwrap_or("guest").to_string())
        .or_else(|| config.nick.clone())
        .or_else(|| session.nick.clone())
        .unwrap_or_else(|| whoami::fallible::username().unwrap_or_else(|_| "guest".to_string()));
    write!(stdout, "  \x1b[1mNickname\x1b[0m [{default_nick}]: ").ok();
    stdout.flush().ok();
    let mut nick_input = String::new();
    stdin.lock().read_line(&mut nick_input).ok();
    let nick_input = nick_input.trim().to_string();
    let nick = if nick_input.is_empty() {
        default_nick
    } else {
        nick_input
    };

    // Server
    let default_server = config
        .server
        .as_deref()
        .or(session.server.as_deref())
        .unwrap_or(DEFAULT_SERVER);
    write!(stdout, "  \x1b[1mServer\x1b[0m [{default_server}]: ").ok();
    stdout.flush().ok();
    let mut server_input = String::new();
    stdin.lock().read_line(&mut server_input).ok();
    let server_input = server_input.trim().to_string();
    let server = if server_input.is_empty() {
        default_server.to_string()
    } else {
        server_input
    };

    // Channel
    let default_channels = config
        .channels
        .as_ref()
        .map(|v| v.join(", "))
        .or_else(|| {
            if session.channels.is_empty() {
                None
            } else {
                Some(session.channels.join(", "))
            }
        })
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
    write!(stdout, "  \x1b[1mChannel\x1b[0m [{default_channels}]: ").ok();
    stdout.flush().ok();
    let mut channel_input = String::new();
    stdin.lock().read_line(&mut channel_input).ok();
    let channel_input = channel_input.trim().to_string();
    let channels: Vec<String> = if channel_input.is_empty() {
        default_channels
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        channel_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Save to config for next time
    let save_cfg = Config {
        server: Some(server.clone()),
        nick: Some(nick.clone()),
        handle: handle.clone(),
        tls: config.tls,
        tls_insecure: config.tls_insecure,
        vi: config.vi,
        channels: Some(channels.clone()),
        iroh_addr: config.iroh_addr.clone(),
        join_part: config.join_part,
    };
    save_cfg.save();

    let tls = config.tls.unwrap_or(false) || server.ends_with(":6697");

    writeln!(stdout).ok();
    if let Some(ref h) = handle {
        writeln!(stdout, "  \x1b[32m→\x1b[0m Connecting to \x1b[1m{server}\x1b[0m as \x1b[1m{nick}\x1b[0m (🦋 {h})").ok();
    } else {
        writeln!(stdout, "  \x1b[32m→\x1b[0m Connecting to \x1b[1m{server}\x1b[0m as \x1b[1m{nick}\x1b[0m (guest)").ok();
    }
    writeln!(stdout).ok();

    Some(Resolved {
        server,
        nick,
        handle,
        tls,
        tls_insecure: config.tls_insecure.unwrap_or(false),
        vi: config.vi.unwrap_or(false),
        channels,
        iroh_addr: config.iroh_addr.clone(),
    })
}
