use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct Config {
    server_addr: String,
    broker_url: String,
    broker_token: String,
    allowed_did: String,
    channel: Option<String>,
    prefix: String,
    outbox_path: String,
    reply_inbox_path: String,
    bot_nick: Option<String>,
    guest_mode: bool,
    fifo_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BrokerSessionResponse {
    token: String,
    nick: String,
}

#[derive(Serialize)]
struct OutboxEntry {
    ts: i64,
    from: String,
    did: String,
    target: String,
    text: String,
}

#[derive(Deserialize)]
struct ReplyEntry {
    target: Option<String>,
    text: String,
}

#[derive(Clone)]
struct PendingCommand {
    target: String,
    text: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cfg = Config {
        server_addr: std::env::var("PI_SERVER_ADDR")
            .unwrap_or_else(|_| "irc.freeq.at:6667".to_string()),
        broker_url: std::env::var("PI_BROKER_URL")
            .unwrap_or_else(|_| "https://auth.freeq.at".to_string()),
        broker_token: std::env::var("PI_BROKER_TOKEN").expect("PI_BROKER_TOKEN required"),
        allowed_did: std::env::var("PI_ALLOWED_DID").expect("PI_ALLOWED_DID required"),
        channel: std::env::var("PI_CHANNEL").ok(),
        prefix: std::env::var("PI_PREFIX").unwrap_or_else(|_| "!pi".to_string()),
        outbox_path: std::env::var("PI_OUTBOX")
            .unwrap_or_else(|_| "/tmp/freeq-pi-queue.jsonl".to_string()),
        reply_inbox_path: std::env::var("PI_REPLY_INBOX")
            .unwrap_or_else(|_| "/tmp/freeq-pi-replies.jsonl".to_string()),
        bot_nick: std::env::var("PI_BOT_NICK").ok(),
        guest_mode: matches!(
            std::env::var("PI_BOT_GUEST").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        ),
        fifo_path: std::env::var("PI_FIFO").ok(),
    };

    loop {
        if let Err(e) = run_once(cfg.clone()).await {
            tracing::warn!(error = %e, "pi-bridge disconnected, retrying in 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn run_once(cfg: Config) -> anyhow::Result<()> {
    let (nick, web_token) = if cfg.guest_mode {
        let nick = cfg
            .bot_nick
            .clone()
            .unwrap_or_else(|| "pi-bridge".to_string());
        tracing::info!(nick = %nick, "pi-bridge guest mode");
        (nick, None)
    } else {
        let session = fetch_broker_session(&cfg).await?;
        let nick = cfg.bot_nick.clone().unwrap_or_else(|| session.nick.clone());
        (nick, Some(session.token))
    };

    let config = ConnectConfig {
        server_addr: cfg.server_addr.clone(),
        nick: nick.clone(),
        user: nick.clone(),
        realname: "freeq pi bridge".to_string(),
        tls: cfg.server_addr.ends_with(":6697") || cfg.server_addr.ends_with(":443"),
        tls_insecure: false,
        web_token,
        websocket_url: None,
    };

    let (handle, mut events) = client::connect(config, None);
    let mut nick_dids: HashMap<String, String> = HashMap::new();
    let mut pending: HashMap<String, PendingCommand> = HashMap::new();
    let mut current_nick = nick.clone();

    // Join control channel after registration
    let channel = cfg.channel.clone();
    let mut registered = false;
    let mut reply_task_started = false;

    while let Some(event) = events.recv().await {
        match event {
            Event::Connected => {
                tracing::info!("pi-bridge connected");
            }
            Event::Registered { nick: confirmed } => {
                tracing::info!(nick = %confirmed, "pi-bridge registered");
                current_nick = confirmed;
                registered = true;
                if let Some(ch) = &channel {
                    tracing::info!(channel = %ch, "joining control channel");
                    let _ = handle.join(ch).await;
                    let _ = handle.privmsg(ch, "pi-bridge online").await;
                }
                if !reply_task_started {
                    reply_task_started = true;
                    let reply_handle = handle.clone();
                    let reply_path = cfg.reply_inbox_path.clone();
                    let reply_channel = channel.clone();
                    tokio::spawn(async move {
                        run_reply_loop(reply_handle, reply_path, reply_channel).await;
                    });
                }
            }
            Event::Authenticated { did } => {
                tracing::info!(%did, "pi-bridge authenticated");
            }
            Event::AuthFailed { reason } => {
                tracing::warn!(%reason, "pi-bridge auth failed");
            }
            Event::NickChanged { old_nick, new_nick } => {
                tracing::info!(from = %old_nick, to = %new_nick, "pi-bridge nick changed");
                if old_nick.eq_ignore_ascii_case(&current_nick) {
                    current_nick = new_nick;
                }
            }
            Event::Joined {
                channel,
                nick: joined_nick,
                ..
            } if joined_nick.eq_ignore_ascii_case(&current_nick) => {
                tracing::info!(channel = %channel, "pi-bridge joined channel");
            }
            Event::ServerNotice { text } => {
                tracing::info!(notice = %text, "server notice");
            }
            Event::RawLine(line) => {
                // Parse ACCOUNT notify: :nick!user@host ACCOUNT did
                if let Some((nick, did)) = parse_account_notify(&line) {
                    tracing::info!(nick = %nick, did = %did, "account notify");
                    nick_dids.insert(nick.to_lowercase(), did);
                }
            }
            Event::WhoisReply { nick, info } => {
                tracing::info!(nick = %nick, info = %info, "whois reply");
                if let Some(did) = parse_whois_did(&info) {
                    let key = nick.to_lowercase();
                    nick_dids.insert(key.clone(), did.clone());
                    if let Some(cmd) = pending.remove(&key) {
                        if did == cfg.allowed_did {
                            tracing::info!(from = %nick, did = %did, "pi command authorized after WHOIS");
                            dispatch_command(
                                &cfg,
                                &OutboxEntry {
                                    ts: chrono::Utc::now().timestamp(),
                                    from: nick.clone(),
                                    did: did.clone(),
                                    target: cmd.target.clone(),
                                    text: cmd.text.clone(),
                                },
                            )?;
                            tracing::info!(from = %nick, "pi command queued after WHOIS");
                            let _ = handle.privmsg(&cmd.target, "✅ queued").await;
                        } else {
                            tracing::warn!(from = %nick, did = %did, "pi command denied after WHOIS");
                            let _ = handle.privmsg(&cmd.target, "Access denied.").await;
                        }
                    }
                }
            }
            Event::Message {
                from,
                target,
                text,
                tags,
                ..
            } => {
                if tags.contains_key("batch") {
                    continue;
                }

                // Only accept DM or control channel
                if let Some(ch) = &channel
                    && !target.eq_ignore_ascii_case(ch)
                    && !target.eq_ignore_ascii_case(&current_nick)
                {
                    continue;
                }

                // Require prefix
                let trimmed = text.trim();
                if !trimmed.starts_with(&cfg.prefix) {
                    continue;
                }
                let payload = trimmed[cfg.prefix.len()..].trim().to_string();
                if payload.is_empty() {
                    continue;
                }

                tracing::info!(from = %from, target = %target, "pi command received");

                let did = match nick_dids.get(&from.to_lowercase()) {
                    Some(d) => d.clone(),
                    None => {
                        tracing::info!(from = %from, "resolving DID via WHOIS");
                        pending.insert(
                            from.to_lowercase(),
                            PendingCommand {
                                target: target.clone(),
                                text: payload.clone(),
                            },
                        );
                        let _ = handle.raw(&format!("WHOIS {from}")).await;
                        let _ = handle
                            .privmsg(&target, "Auth pending — resolving DID…")
                            .await;
                        continue;
                    }
                };

                if did != cfg.allowed_did {
                    tracing::warn!(from = %from, did = %did, "pi command denied");
                    let _ = handle.privmsg(&target, "Access denied.").await;
                    continue;
                }

                tracing::info!(from = %from, did = %did, "pi command authorized");
                dispatch_command(
                    &cfg,
                    &OutboxEntry {
                        ts: chrono::Utc::now().timestamp(),
                        from: from.clone(),
                        did,
                        target: target.clone(),
                        text: payload.clone(),
                    },
                )?;

                tracing::info!(from = %from, "pi command queued");
                let _ = handle.privmsg(&target, "✅ queued").await;
            }
            Event::Disconnected { reason } => {
                tracing::warn!(%reason, "Disconnected");
                break;
            }
            _ => {}
        }
    }

    if registered {
        tracing::info!("pi-bridge connection ended");
    }

    Ok(())
}

async fn fetch_broker_session(cfg: &Config) -> anyhow::Result<BrokerSessionResponse> {
    let url = format!("{}/session", cfg.broker_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"broker_token": cfg.broker_token}))
        .send()
        .await?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("broker session failed: {text}"));
    }
    Ok(resp.json().await?)
}

fn write_outbox(path: &str, entry: &OutboxEntry) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(entry)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn dispatch_command(cfg: &Config, entry: &OutboxEntry) -> anyhow::Result<()> {
    write_outbox(&cfg.outbox_path, entry)?;
    tracing::info!(target = %entry.target, "pi command written to outbox");
    if let Some(ref fifo) = cfg.fifo_path {
        if let Err(err) = write_fifo(fifo, &entry.text) {
            tracing::warn!(error = %err, fifo = %fifo, "Failed to write to FIFO");
        } else {
            tracing::info!(fifo = %fifo, "pi command written to FIFO");
        }
    }
    Ok(())
}

fn write_fifo(path: &str, text: &str) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    writeln!(file, "{text}")?;
    Ok(())
}

fn parse_account_notify(line: &str) -> Option<(String, String)> {
    // :nick!user@host ACCOUNT did
    if !line.contains(" ACCOUNT ") {
        return None;
    }
    let mut parts = line.splitn(3, ' ');
    let prefix = parts.next()?;
    let cmd = parts.next()?;
    if cmd != "ACCOUNT" {
        return None;
    }
    let did = parts.next()?.trim();
    let nick = prefix.trim_start_matches(':').split('!').next()?;
    Some((nick.to_string(), did.to_string()))
}

fn parse_whois_did(info: &str) -> Option<String> {
    // "nick is authenticated as did:plc:..."
    if let Some(idx) = info.find("did:") {
        return Some(info[idx..].trim().to_string());
    }
    None
}

async fn run_reply_loop(
    handle: client::ClientHandle,
    path: String,
    default_target: Option<String>,
) {
    let mut offset: u64 = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match read_reply_entries(&path, &mut offset) {
            Ok(entries) => {
                for entry in entries {
                    let target = entry.target.as_ref().or(default_target.as_ref());
                    if let Some(target) = target {
                        let _ = handle.privmsg(target, &entry.text).await;
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to read reply inbox");
            }
        }
    }
}

fn read_reply_entries(path: &str, offset: &mut u64) -> anyhow::Result<Vec<ReplyEntry>> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(err) => return Err(err.into()),
    };
    let len = file.metadata()?.len();
    if len < *offset {
        *offset = 0;
    }
    file.seek(SeekFrom::Start(*offset))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    *offset = file.seek(SeekFrom::End(0))?;

    let mut entries = Vec::new();
    for line in buf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<ReplyEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(err) => tracing::warn!(error = %err, "Invalid reply entry"),
        }
    }

    Ok(entries)
}
