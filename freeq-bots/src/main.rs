//! freeq-bots: AI agents that do real work in IRC channels.
//!
//! Runs as a single process connecting to a freeq server. Handles multiple
//! bot personas in the same channel. Commands:
//!
//!   /factory build <spec>     — Start the software factory
//!   /factory status           — Check factory status
//!   /factory pause / resume   — Control the pipeline
//!   /audit <repo-url>         — Architecture audit
//!   /prototype <spec>         — Quick spec-to-deployed-prototype
//!   /help                     — List commands
//!
//! Requires ANTHROPIC_API_KEY environment variable.

use anyhow::Result;
use clap::Parser;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;
use std::path::PathBuf;

use freeq_bots::factory::{Factory, FactoryConfig};
use freeq_bots::llm::LlmClient;
use freeq_bots::memory::Memory;
use freeq_bots::output::{self, AgentId};

#[derive(Parser)]
#[command(name = "freeq-bots", about = "AI agent bots for freeq IRC")]
struct Args {
    /// IRC server address (host:port)
    #[arg(long, default_value = "irc.freeq.at:6667")]
    server: String,

    /// Bot nick
    #[arg(long, default_value = "factory")]
    nick: String,

    /// Channel to join
    #[arg(long, default_value = "#factory")]
    channel: String,

    /// Use TLS
    #[arg(long)]
    tls: bool,

    /// Workspace directory for generated projects
    #[arg(long, default_value = "/tmp/freeq-bots")]
    workspace: PathBuf,

    /// Memory database path
    #[arg(long, default_value = "/tmp/freeq-bots/memory.db")]
    memory_db: PathBuf,

    /// Claude model to use
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    model: String,

    /// Anthropic API key (or set ANTHROPIC_API_KEY env var)
    #[arg(long, env = "ANTHROPIC_API_KEY")]
    api_key: String,

    /// Command prefix
    #[arg(long, default_value = "/")]
    prefix: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "freeq_bots=info".into()),
        )
        .init();

    let args = Args::parse();

    // Create workspace directory
    tokio::fs::create_dir_all(&args.workspace).await?;
    if let Some(parent) = args.memory_db.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Initialize components
    let llm = LlmClient::new(args.api_key.clone()).with_model(&args.model);
    let memory = Memory::open(&args.memory_db)?;
    let factory = Factory::new(FactoryConfig {
        channel: args.channel.clone(),
        workspace_base: args.workspace.clone(),
    });

    tracing::info!(
        server = %args.server,
        nick = %args.nick,
        channel = %args.channel,
        "Starting freeq-bots"
    );

    // Connect to IRC
    let conn = client::establish_connection(&ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "freeq AI factory bot".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    })
    .await?;

    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "freeq AI factory bot".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
    };

    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    // Join channel after registration
    let channel = args.channel.clone();
    let h2 = handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = h2.join(&channel).await;
        tracing::info!("Joined {channel}");
    });

    let bot_nick = args.nick.clone();

    tracing::info!("Bot running. Ctrl+C to stop.");

    // Event loop
    loop {
        match events.recv().await {
            Some(event) => {
                if let Err(e) =
                    handle_event(&handle, &bot_nick, &args, &event, &llm, &memory, &factory).await
                {
                    tracing::error!(error = %e, "Event handler error");
                }
            }
            None => {
                tracing::warn!("Event channel closed, exiting");
                break;
            }
        }
    }

    Ok(())
}

fn system_agent() -> AgentId {
    AgentId {
        role: "system".to_string(),
        color: None,
    }
}

async fn handle_event(
    handle: &ClientHandle,
    bot_nick: &str,
    args: &Args,
    event: &Event,
    llm: &LlmClient,
    memory: &Memory,
    factory: &Factory,
) -> Result<()> {
    match event {
        Event::Connected => tracing::info!("Connected"),
        Event::Registered { nick } => tracing::info!("Registered as {nick}"),

        Event::Joined { channel, nick, .. } if nick == bot_nick => {
            output::status(handle, channel, &system_agent(), "🤖",
                    "AI Factory online. Commands: /factory build <spec> | /audit <repo> | /prototype <spec> | /help"
                ).await?;
        }

        Event::Message {
            from,
            target,
            text,
            tags,
            ..
        } => {
            if tags.contains_key("batch") {
                return Ok(());
            }
            // Ignore our own messages
            if from == bot_nick {
                return Ok(());
            }

            let is_channel = target.starts_with('#') || target.starts_with('&');
            if !is_channel {
                return Ok(());
            }

            let channel = target;

            // Parse commands
            if let Some(cmd_text) = text.strip_prefix(&args.prefix) {
                let parts: Vec<&str> = cmd_text.splitn(2, ' ').collect();
                let cmd = parts[0].to_lowercase();
                let cmd_args = parts.get(1).unwrap_or(&"").trim();

                match cmd.as_str() {
                    "factory" => {
                        let sub_parts: Vec<&str> = cmd_args.splitn(2, ' ').collect();
                        let sub_cmd = sub_parts.first().unwrap_or(&"status");
                        let sub_args = sub_parts.get(1).unwrap_or(&"");
                        factory
                            .handle_command(handle, channel, from, sub_cmd, sub_args, llm, memory)
                            .await?;
                    }

                    "audit" => {
                        if cmd_args.is_empty() {
                            output::say(
                                handle,
                                channel,
                                &system_agent(),
                                "Usage: /audit <github-url or repo-path>",
                            )
                            .await?;
                        } else {
                            let h = handle.clone();
                            let ch = channel.to_string();
                            let target = cmd_args.to_string();
                            let llm_key = args.api_key.clone();
                            let model = args.model.clone();
                            let ws = args.workspace.clone();
                            tokio::spawn(async move {
                                let llm = LlmClient::new(llm_key).with_model(&model);
                                if let Err(e) =
                                    freeq_bots::auditor::audit(&h, &ch, &target, &llm, &ws).await
                                {
                                    tracing::error!(error = %e, "Audit failed");
                                    let _ = output::error(
                                        &h,
                                        &ch,
                                        &AgentId {
                                            role: "auditor".to_string(),
                                            color: None,
                                        },
                                        &format!("Audit failed: {e}"),
                                    )
                                    .await;
                                }
                            });
                        }
                    }

                    "prototype" | "proto" => {
                        if cmd_args.is_empty() {
                            output::say(
                                handle,
                                channel,
                                &system_agent(),
                                "Usage: /prototype <describe what to build>",
                            )
                            .await?;
                        } else {
                            let h = handle.clone();
                            let ch = channel.to_string();
                            let spec = cmd_args.to_string();
                            let llm_key = args.api_key.clone();
                            let model = args.model.clone();
                            let ws = args.workspace.clone();
                            let db = args.memory_db.clone();
                            tokio::spawn(async move {
                                let llm = LlmClient::new(llm_key).with_model(&model);
                                let mem = match Memory::open(&db) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        tracing::error!("Failed to open memory: {e}");
                                        return;
                                    }
                                };
                                if let Err(e) =
                                    freeq_bots::prototype::build(&h, &ch, &spec, &llm, &mem, &ws)
                                        .await
                                {
                                    tracing::error!(error = %e, "Prototype build failed");
                                    let _ = output::error(
                                        &h,
                                        &ch,
                                        &AgentId {
                                            role: "builder".to_string(),
                                            color: None,
                                        },
                                        &format!("Build failed: {e}"),
                                    )
                                    .await;
                                }
                            });
                        }
                    }

                    "help" | "h" => {
                        let lines = [
                            "🤖 freeq AI Factory — Commands:",
                            "/factory build <spec>  — Full software factory pipeline",
                            "/factory status        — Current factory status",
                            "/factory pause/resume  — Control the pipeline",
                            "/factory spec          — Show current project spec",
                            "/factory files         — List project files",
                            "/audit <repo-url>      — Architecture audit of a GitHub repo",
                            "/prototype <spec>      — Quick spec → deployed prototype",
                            "/help                  — This help message",
                        ];
                        for line in &lines {
                            handle.privmsg(channel, line).await?;
                            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                        }
                    }

                    _ => {} // Ignore unknown commands silently
                }
            }
        }

        Event::Disconnected { reason } => {
            tracing::warn!("Disconnected: {reason}");
        }

        _ => {}
    }

    Ok(())
}
