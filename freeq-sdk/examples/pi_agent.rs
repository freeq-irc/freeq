//! Pi remote agent — controllable via IRC by chadfowler.com only.
//!
//! Commands (in channel or DM):
//!   pi: <bash command>        — run a shell command
//!   pi: read <path>           — read a file (first 50 lines)
//!   pi: edit <path>           — show file for context
//!   pi: cd <dir>              — change working directory
//!   pi: status                — show cwd, uptime, load
//!   pi: quit                  — disconnect
//!
//! Usage:
//!   cargo run --example pi_agent -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

const OWNER: &str = "chadfowler.com";
const MAX_LINES: usize = 30;
const MAX_BYTES: usize = 1500; // IRC message limit safety

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "pi")]
    nick: String,
    #[arg(long, default_value = "#chad-dev")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

async fn drain(rx: &mut mpsc::Receiver<Event>) {
    tokio::time::sleep(Duration::from_secs(4)).await;
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), rx.recv()).await {}
}

/// Send multi-line output to a channel, respecting IRC limits.
async fn send_output(h: &ClientHandle, target: &str, output: &str) {
    if output.trim().is_empty() {
        let _ = h.privmsg(target, "(no output)").await;
        return;
    }

    let lines: Vec<&str> = output.lines().collect();
    let total = lines.len();
    let mut sent_bytes = 0;
    let mut sent_lines = 0;

    for line in &lines {
        if sent_lines >= MAX_LINES || sent_bytes > MAX_BYTES {
            let _ = h
                .privmsg(
                    target,
                    &format!("... ({} more lines truncated)", total - sent_lines),
                )
                .await;
            break;
        }
        // Truncate very long lines
        let display = if line.len() > 400 {
            format!("{}...", &line[..400])
        } else {
            line.to_string()
        };
        let _ = h.privmsg(target, &display).await;
        sent_bytes += display.len();
        sent_lines += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Execute a bash command with timeout, return stdout+stderr.
async fn run_cmd(cmd: &str, cwd: &PathBuf) -> String {
    let result = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        .output()
        .await;

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut result = String::new();
            if !stdout.is_empty() {
                result.push_str(&stdout);
            }
            if !stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&stderr);
            }
            if !output.status.success() {
                result.push_str(&format!(
                    "\n(exit code: {})",
                    output.status.code().unwrap_or(-1)
                ));
            }
            result
        }
        Err(e) => format!("Error: {e}"),
    }
}

/// Read a file, return first N lines.
async fn read_file(path: &str, cwd: &PathBuf) -> String {
    let full_path = if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };

    match tokio::fs::read_to_string(&full_path).await {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let total = lines.len();
            let show = lines.into_iter().take(50).collect::<Vec<_>>().join("\n");
            if total > 50 {
                format!("{show}\n... ({total} lines total, showing first 50)")
            } else {
                show
            }
        }
        Err(e) => format!("Error reading {}: {e}", full_path.display()),
    }
}

async fn handle_command(h: &ClientHandle, target: &str, text: &str, cwd: &mut PathBuf) -> bool {
    let text = text.trim();

    if text.eq_ignore_ascii_case("quit") || text.eq_ignore_ascii_case("exit") {
        let _ = h.privmsg(target, "👋 Shutting down.").await;
        return true; // signal quit
    }

    if text.eq_ignore_ascii_case("status") {
        let uptime = run_cmd("uptime", cwd).await;
        let _ = h.privmsg(target, &format!("cwd: {}", cwd.display())).await;
        let _ = h
            .privmsg(target, &format!("uptime: {}", uptime.trim()))
            .await;
        return false;
    }

    if let Some(dir) = text.strip_prefix("cd ") {
        let dir = dir.trim();
        let new_path = if dir.starts_with('/') {
            PathBuf::from(dir)
        } else if dir.starts_with('~') {
            dirs::home_dir()
                .unwrap_or_default()
                .join(dir.strip_prefix("~/").unwrap_or(dir))
        } else {
            cwd.join(dir)
        };
        match std::fs::canonicalize(&new_path) {
            Ok(canonical) => {
                *cwd = canonical;
                let _ = h.privmsg(target, &format!("cd {}", cwd.display())).await;
            }
            Err(e) => {
                let _ = h.privmsg(target, &format!("cd failed: {e}")).await;
            }
        }
        return false;
    }

    if let Some(path) = text.strip_prefix("read ") {
        let output = read_file(path.trim(), cwd).await;
        send_output(h, target, &output).await;
        return false;
    }

    // Default: run as bash command
    let _ = h.privmsg(target, &format!("$ {text}")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run with 30s timeout
    let output = tokio::time::timeout(Duration::from_secs(30), run_cmd(text, cwd)).await;
    match output {
        Ok(out) => send_output(h, target, &out).await,
        Err(_) => {
            let _ = h.privmsg(target, "(command timed out after 30s)").await;
        }
    }

    false
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let ch = &args.channel;

    // Load or generate persistent key
    let key_dir = dirs::home_dir().unwrap().join(".freeq/bots/pi");
    std::fs::create_dir_all(&key_dir)?;
    let key_path = key_dir.join("key.ed25519");
    let private_key = if key_path.exists() {
        PrivateKey::ed25519_from_bytes(&std::fs::read(&key_path)?)?
    } else {
        let key = PrivateKey::generate_ed25519();
        std::fs::write(&key_path, key.secret_bytes())?;
        key
    };
    let did = format!("did:key:{}", private_key.public_key_multibase());
    println!("DID: {did}");
    let signer = KeySigner::new(did.clone(), private_key);

    println!("Connecting to {}...", args.server);
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "pi remote agent".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    };
    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) =
        client::connect_with_stream(conn, config, Some(std::sync::Arc::new(signer)));

    // Wait for registration
    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                println!("Registered as {nick}");
                break;
            }
            Some(Event::Disconnected { reason }) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            _ => continue,
        }
    }

    // Agent setup
    handle.register_agent("agent").await?;
    handle.raw("HEARTBEAT 60").await?;
    handle
        .raw("PRESENCE :state=active;status=Listening for commands")
        .await?;
    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:4qsyxmnsblo4luuycm3572bq",
        "implementation_ref": "freeq/pi_agent.rs@HEAD",
        "source_repo": "https://github.com/freeq-irc/freeq",
        "authority_basis": "Operated by server administrator",
        "revocation_authority": "did:plc:4qsyxmnsblo4luuycm3572bq",
    });
    handle
        .raw(&format!(
            "PROVENANCE :{}",
            b64(&serde_json::to_vec(&provenance)?)
        ))
        .await?;

    handle.join(ch).await?;
    drain(&mut events).await;

    let mut cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    println!("Ready. cwd={} Listening in {ch}", cwd.display());

    let _ = handle
        .privmsg(
            ch,
            &format!(
                "🖥 pi agent online. cwd: {}. Only {OWNER} can control me.",
                cwd.display()
            ),
        )
        .await;

    // Main loop
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let hb_remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        match timeout(hb_remaining, events.recv()).await {
            Ok(Some(Event::Message {
                from,
                target,
                text,
                tags,
                ..
            })) => {
                if tags.contains_key("batch") {
                    continue;
                }

                // Only respond to OWNER
                if !from.eq_ignore_ascii_case(OWNER) {
                    continue;
                }

                // Extract command — either "pi: <cmd>" in channel or direct DM
                let cmd = if target.eq_ignore_ascii_case(ch) {
                    // Channel message — needs "pi:" prefix
                    let trimmed = text.trim();
                    let lower = trimmed.to_lowercase();
                    let rest = if lower.starts_with("pi: ") || lower.starts_with("pi:") {
                        Some(&trimmed[3..])
                    } else if lower.starts_with("pi, ") || lower.starts_with("pi,") {
                        Some(&trimmed[3..])
                    } else if lower.starts_with("@pi ") {
                        Some(&trimmed[4..])
                    } else {
                        None
                    };
                    rest.map(|r| (ch.to_string(), r.trim().to_string()))
                } else {
                    // DM — everything is a command
                    Some((from.clone(), text.trim().to_string()))
                };

                if let Some((reply_to, cmd_text)) = cmd {
                    if cmd_text.is_empty() {
                        continue;
                    }

                    handle
                        .raw("PRESENCE :state=executing;status=Running command")
                        .await?;

                    let should_quit = handle_command(&handle, &reply_to, &cmd_text, &mut cwd).await;

                    if should_quit {
                        break;
                    }

                    handle
                        .raw(&format!(
                            "PRESENCE :state=active;status=Listening (cwd: {})",
                            cwd.display()
                        ))
                        .await?;
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                // Heartbeat
                handle.raw("HEARTBEAT 60").await?;
                last_hb = tokio::time::Instant::now();
            }
        }
    }

    handle
        .raw("PRESENCE :state=offline;status=Shutting down")
        .await?;
    handle.quit(Some("pi agent signing off")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Done.");
    Ok(())
}
