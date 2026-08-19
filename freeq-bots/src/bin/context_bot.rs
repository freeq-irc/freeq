//! Context-aware chatbot — demonstrates tiered context persistence.
//!
//! This bot maintains conversation context across restarts using:
//! - CHATHISTORY replay (fetches recent messages on connect)
//! - Rolling summaries (periodically compresses conversation)
//! - Structured fact extraction (stores decisions, preferences, action items)
//! - Persistent SQLite memory
//!
//! Usage:
//!   ANTHROPIC_API_KEY=sk-... cargo run --release --bin context-bot -- \
//!     --server 127.0.0.1:6667 --channel '#test' --nick contextbot
//!
//! The bot responds when addressed by name ("contextbot: what did we discuss?")
//! and maintains context even after being restarted.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;

use freeq_bots::context::{AgentContext, AgentIdentity, ContextConfig, HistoryMessage};
use freeq_bots::llm::LlmClient;
use freeq_bots::memory::Memory;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;

#[derive(Parser)]
#[command(name = "context-bot", about = "Context-aware IRC chatbot")]
struct Args {
    /// IRC server address
    #[arg(long, default_value = "127.0.0.1:6667")]
    server: String,

    /// Channel to join
    #[arg(long, default_value = "#test")]
    channel: String,

    /// Bot nickname
    #[arg(long, default_value = "contextbot")]
    nick: String,

    /// Path to SQLite memory database
    #[arg(long, default_value = "context-bot.db")]
    db: PathBuf,

    /// Claude model to use
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    model: String,

    /// Messages to fetch from history on connect
    #[arg(long, default_value = "50")]
    history_count: usize,

    /// Messages between automatic summaries
    #[arg(long, default_value = "30")]
    summary_every: usize,

    /// Extract facts every N messages addressed to the bot
    #[arg(long, default_value = "5")]
    extract_every: usize,

    /// Use TLS
    #[arg(long)]
    tls: bool,

    /// Use guest mode (no SASL auth)
    #[arg(long)]
    guest: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let args = Args::parse();
    let api_key =
        std::env::var("ANTHROPIC_API_KEY").expect("Set ANTHROPIC_API_KEY environment variable");

    let memory = Arc::new(Memory::open(&args.db)?);
    tracing::info!(db = %args.db.display(), "Opened memory database");

    let llm = LlmClient::new(api_key).with_model(&args.model);

    let identity = AgentIdentity {
        nick: args.nick.clone(),
        did: None,
        role: "A helpful, context-aware IRC assistant that remembers conversations across restarts"
            .into(),
        channels: vec![args.channel.clone()],
        system_prompt: Some(
            "You are a helpful IRC chatbot. Keep responses concise (1-3 sentences for simple \
             questions, more for complex topics). You have access to conversation history, \
             summaries, and stored facts — use them to maintain continuity. \
             When someone asks what you remember or what was discussed, refer to your context. \
             Do NOT prefix your messages with your nick."
                .into(),
        ),
    };

    let config = ContextConfig {
        history_fetch_count: args.history_count,
        recent_window_size: 100,
        summary_threshold: args.summary_every,
        summary_interval_minutes: 15,
        max_facts: 50,
        max_context_tokens: 10_000,
    };

    let ctx = Arc::new(AgentContext::new(identity, memory, config));

    loop {
        tracing::info!(server = %args.server, "Connecting...");
        match run_once(&args, &llm, &ctx).await {
            Ok(()) => {
                tracing::info!("Clean disconnect");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "Disconnected, reconnecting in 5s...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}

async fn run_once(args: &Args, llm: &LlmClient, ctx: &Arc<AgentContext>) -> Result<()> {
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: "contextbot".into(),
        realname: "Freeq Context Bot".into(),
        tls: args.tls,
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, None);

    // Wait for registration
    wait_for_registration(&mut events).await?;
    tracing::info!("Registered as {}", args.nick);

    // Join channel
    handle.join(&args.channel).await?;
    tracing::info!(channel = %args.channel, "Joining channel");

    // Wait for join confirmation
    wait_for_join(&mut events, &args.channel).await?;

    // ── Tier 3: Fetch and ingest CHATHISTORY ──────────────────────────
    let count = ctx
        .fetch_and_ingest(&handle, &mut events, &args.channel)
        .await?;
    tracing::info!(channel = %args.channel, count, "Ingested history");

    // Announce presence
    let msg_count = ctx.message_count(&args.channel).await;
    let has_summary = ctx
        .assemble(&args.channel, None)
        .await
        .contains("Conversation Summary");

    let status = if has_summary {
        format!(
            "Back online. I have {msg_count} recent messages and a conversation summary in context."
        )
    } else if msg_count > 0 {
        format!("Back online. Loaded {msg_count} messages from history.")
    } else {
        "Online. No prior history for this channel.".into()
    };

    handle.privmsg(&args.channel, &status).await?;

    // ── Main event loop ───────────────────────────────────────────────
    let mut exchanges_since_extract = 0u32;

    loop {
        let event = match events.recv().await {
            Some(e) => e,
            None => return Err(anyhow::anyhow!("Event channel closed")),
        };

        match event {
            Event::Message {
                from,
                target,
                text,
                tags,
                ..
            } if target == args.channel => {
                // Record every message
                let timestamp = tags
                    .get("time")
                    .and_then(|t| {
                        chrono::DateTime::parse_from_rfc3339(t)
                            .ok()
                            .map(|dt| dt.timestamp() as u64)
                    })
                    .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64);

                ctx.record_message(
                    &args.channel,
                    HistoryMessage {
                        nick: from.clone(),
                        text: text.clone(),
                        timestamp,
                        msgid: tags.get("msgid").cloned(),
                        tags: tags.clone(),
                    },
                )
                .await;

                // Check if addressed to us
                if let Some(query) = is_addressed_to(&text, &args.nick) {
                    tracing::info!(from = %from, query, "Addressed by user");

                    // Handle special commands
                    let query_lower = query.trim().to_lowercase();
                    if query_lower == "summarize" || query_lower == "summary" {
                        // Force a summary
                        match ctx.maybe_summarize(&args.channel, None, llm).await {
                            Ok(true) => {
                                handle
                                    .privmsg(&args.channel, "Summary updated and stored.")
                                    .await?;
                            }
                            Ok(false) => {
                                handle
                                    .privmsg(&args.channel, "Not enough new messages to summarize.")
                                    .await?;
                            }
                            Err(e) => {
                                handle
                                    .privmsg(&args.channel, &format!("Summary failed: {e}"))
                                    .await?;
                            }
                        }
                        continue;
                    }

                    if query_lower == "context" || query_lower == "status" {
                        // Dump context info
                        let msg_count = ctx.message_count(&args.channel).await;
                        let assembled = ctx.assemble(&args.channel, None).await;
                        let approx_tokens = assembled.len() / 4; // rough estimate
                        let status_msg = format!(
                            "Context: ~{approx_tokens} tokens | {msg_count} recent messages in window | DB: {}",
                            args.db.display()
                        );
                        handle.privmsg(&args.channel, &status_msg).await?;
                        continue;
                    }

                    if query_lower.starts_with("remember ") {
                        // Explicit fact storage
                        let fact = query_lower.strip_prefix("remember ").unwrap();
                        ctx.store(
                            args.channel.trim_start_matches('#'),
                            "fact",
                            &format!("user_{}", chrono::Utc::now().timestamp()),
                            fact,
                        )?;
                        handle
                            .privmsg(&args.channel, &format!("Stored: {fact}"))
                            .await?;
                        continue;
                    }

                    if query_lower.starts_with("forget ") {
                        let key = query_lower.strip_prefix("forget ").unwrap().trim();
                        ctx.clear(args.channel.trim_start_matches('#'), "fact", key)?;
                        handle
                            .privmsg(&args.channel, &format!("Forgot: {key}"))
                            .await?;
                        continue;
                    }

                    // Regular LLM response with full context
                    let system = ctx.assemble(&args.channel, None).await;

                    let user_prompt = format!(
                        "<{from}> {query}\n\n\
                         Respond naturally. Use your context (conversation history, \
                         summaries, stored facts) to give informed answers."
                    );

                    match llm.complete(&system, &user_prompt).await {
                        Ok(response) => {
                            // Send response (split long messages)
                            for line in split_irc_message(&response, 400) {
                                handle.privmsg(&args.channel, &line).await?;
                            }

                            // Record our own response
                            ctx.record_message(
                                &args.channel,
                                HistoryMessage {
                                    nick: args.nick.clone(),
                                    text: response.clone(),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                    msgid: None,
                                    tags: HashMap::new(),
                                },
                            )
                            .await;

                            // Periodic fact extraction
                            exchanges_since_extract += 1;
                            if exchanges_since_extract >= args.extract_every as u32 {
                                let exchange =
                                    format!("<{from}> {query}\n<{}> {response}", args.nick);
                                if let Err(e) =
                                    ctx.extract_facts(&args.channel, None, &exchange, llm).await
                                {
                                    tracing::warn!(error = %e, "Fact extraction failed");
                                }
                                exchanges_since_extract = 0;
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "LLM call failed");
                            handle
                                .privmsg(&args.channel, &format!("Error: {e}"))
                                .await?;
                        }
                    }

                    // Check if summary is needed
                    if let Err(e) = ctx.maybe_summarize(&args.channel, None, llm).await {
                        tracing::warn!(error = %e, "Summary generation failed");
                    }
                }
            }

            Event::Disconnected { reason } => {
                // Export context file before disconnecting
                let path = std::env::temp_dir().join(format!(
                    "freeq-context-{}.md",
                    args.channel.replace('#', "")
                ));
                if let Err(e) = ctx.export_context_file(&args.channel, None, &path).await {
                    tracing::warn!(error = %e, "Failed to export context file");
                } else {
                    tracing::info!(path = %path.display(), "Exported context file");
                }
                return Err(anyhow::anyhow!("Disconnected: {reason}"));
            }

            _ => {}
        }
    }
}

/// Check if a message is addressed to the bot.
/// Returns the message text after the address prefix, or None.
fn is_addressed_to<'a>(text: &'a str, nick: &str) -> Option<&'a str> {
    let lower = text.to_lowercase();
    let nick_lower = nick.to_lowercase();

    // "nick: message" or "nick, message" or "@nick message"
    for prefix in [
        format!("{nick_lower}: "),
        format!("{nick_lower}, "),
        format!("@{nick_lower} "),
    ] {
        if lower.starts_with(&prefix) {
            return Some(&text[prefix.len()..]);
        }
    }
    // "nick:" or "nick," with no space (less common but valid)
    for prefix in [format!("{nick_lower}:"), format!("{nick_lower},")] {
        if lower.starts_with(&prefix) && text.len() > prefix.len() {
            return Some(text[prefix.len()..].trim_start());
        }
    }
    None
}

/// Split a long message into IRC-safe chunks.
fn split_irc_message(text: &str, max_len: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.len() <= max_len {
            lines.push(line.to_string());
        } else {
            let mut remaining = line;
            while remaining.len() > max_len {
                let split_at = remaining[..max_len].rfind(' ').unwrap_or(max_len);
                lines.push(remaining[..split_at].to_string());
                remaining = remaining[split_at..].trim_start();
            }
            if !remaining.is_empty() {
                lines.push(remaining.to_string());
            }
        }
    }
    if lines.is_empty() {
        lines.push(text.to_string());
    }
    lines
}

async fn wait_for_registration(events: &mut mpsc::Receiver<Event>) -> Result<()> {
    let timeout = tokio::time::Duration::from_secs(10);
    loop {
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Some(Event::Registered { .. })) => return Ok(()),
            Ok(Some(Event::Disconnected { reason })) => {
                return Err(anyhow::anyhow!(
                    "Disconnected during registration: {reason}"
                ));
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Err(anyhow::anyhow!("Event channel closed")),
            Err(_) => return Err(anyhow::anyhow!("Registration timed out")),
        }
    }
}

async fn wait_for_join(events: &mut mpsc::Receiver<Event>, channel: &str) -> Result<()> {
    let timeout = tokio::time::Duration::from_secs(10);
    loop {
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Some(Event::Joined { channel: ch, .. })) if ch == channel => return Ok(()),
            Ok(Some(Event::Disconnected { reason })) => {
                return Err(anyhow::anyhow!("Disconnected during join: {reason}"));
            }
            Ok(Some(_)) => continue,
            Ok(None) => return Err(anyhow::anyhow!("Event channel closed")),
            Err(_) => return Err(anyhow::anyhow!("Join timed out")),
        }
    }
}
