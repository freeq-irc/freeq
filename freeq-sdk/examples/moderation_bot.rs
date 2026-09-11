//! Moderation bot example — demonstrates threads, reactions, rate limiting,
//! robust reconnect, and admin commands.
//!
//! Usage:
//!   cargo run --example moderation_bot -- --server irc.freeq.at:6697 --tls \
//!     --channel "#bots" --admin-did did:plc:...
//!
//! Features demonstrated:
//!   - Command routing with permissions (anyone / auth / admin)
//!   - Per-user rate limiting (5 commands per 30s)
//!   - Input size caps (500 chars)
//!   - Thread replies and reactions
//!   - Typing indicators
//!   - History fetching
//!   - Automatic reconnect with exponential backoff
//!   - Fallback handler for non-command messages

use anyhow::Result;
use clap::Parser;
use freeq_sdk::bot::Bot;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig, ReconnectConfig};
use freeq_sdk::event::Event;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "moderation-bot", about = "Freeq moderation bot example")]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "modbot")]
    nick: String,
    #[arg(long, default_value = "#bots")]
    channel: String,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    admin_did: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Build bot with rate limiting and input caps
    let mut bot = Bot::new("!", &args.nick)
        .rate_limit(5, Duration::from_secs(30))
        .max_args(500);

    if let Some(ref did) = args.admin_did {
        bot = bot.admin(did);
    }

    // ── Anyone commands ──

    bot.command("ping", "Check if the bot is alive", |ctx| {
        Box::pin(async move {
            ctx.react("🏓").await?;
            ctx.reply_to("pong!").await
        })
    });

    bot.command("whoami", "Show your identity", |ctx| {
        Box::pin(async move {
            let info = match &ctx.sender_did {
                Some(did) => format!("✓ {}: authenticated as `{did}`", ctx.sender),
                None => format!("👤 {}: guest (not authenticated)", ctx.sender),
            };
            ctx.reply_in_thread(&info).await
        })
    });

    bot.command("echo", "Echo your message back", |ctx| {
        Box::pin(async move {
            let text = ctx.args_str();
            if text.is_empty() {
                ctx.reply("Usage: !echo <message>").await
            } else {
                ctx.reply(&text).await
            }
        })
    });

    bot.command("history", "Fetch recent history (default: 10)", |ctx| {
        Box::pin(async move {
            let count: usize = ctx
                .arg(0)
                .and_then(|s| s.parse().ok())
                .unwrap_or(10)
                .min(50);
            ctx.handle.history_latest(ctx.reply_target(), count).await?;
            ctx.reply(&format!("Requested {count} messages of history."))
                .await
        })
    });

    // ── Authenticated commands ──

    bot.auth_command("greet", "Get a personalized greeting", |ctx| {
        Box::pin(async move {
            ctx.typing().await?;
            // Simulate "thinking"
            tokio::time::sleep(Duration::from_millis(500)).await;
            ctx.typing_done().await?;
            let did = ctx.sender_did.as_deref().unwrap_or("unknown");
            ctx.reply_to(&format!("Welcome, verified user! Your DID: `{did}`"))
                .await
        })
    });

    // ── Admin commands ──

    bot.admin_command("kick", "Kick a user from the channel", |ctx| {
        Box::pin(async move {
            let nick = match ctx.arg(0) {
                Some(n) => n.to_string(),
                None => return ctx.reply("Usage: !kick <nick> [reason]").await,
            };
            let reason = if ctx.args.len() > 1 {
                ctx.args[1..].join(" ")
            } else {
                "Kicked by modbot".to_string()
            };
            ctx.handle
                .raw(&format!("KICK {} {} :{}", ctx.target, nick, reason))
                .await?;
            ctx.react("👢").await
        })
    });

    bot.admin_command("topic", "Set the channel topic", |ctx| {
        Box::pin(async move {
            let text = ctx.args_str();
            if text.is_empty() {
                return ctx.reply("Usage: !topic <new topic>").await;
            }
            ctx.handle.topic(&ctx.target, &text).await?;
            ctx.react("✅").await
        })
    });

    bot.admin_command("op", "Give ops to a user", |ctx| {
        Box::pin(async move {
            match ctx.arg(0) {
                Some(nick) => {
                    ctx.handle.mode(&ctx.target, "+o", Some(nick)).await?;
                    ctx.react("👑").await
                }
                None => ctx.reply("Usage: !op <nick>").await,
            }
        })
    });

    bot.admin_command("voice", "Give voice to a user", |ctx| {
        Box::pin(async move {
            match ctx.arg(0) {
                Some(nick) => {
                    ctx.handle.mode(&ctx.target, "+v", Some(nick)).await?;
                    ctx.react("🎤").await
                }
                None => ctx.reply("Usage: !voice <nick>").await,
            }
        })
    });

    // ── Fallback: auto-react to mentions ──

    bot.on_message(|ctx| {
        Box::pin(async move {
            // React with 👋 when someone says "hello" or "hi"
            let lower = ctx.args_raw.to_lowercase();
            if lower.contains("hello") || lower.contains("hi ") || lower == "hi" {
                ctx.react("👋").await?;
            }
            Ok(())
        })
    });

    // ── Connect with auto-reconnect ──

    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "freeq moderation bot".to_string(),
        tls: args.tls || args.server.ends_with(":6697"),
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
        ..Default::default()
    };

    let reconnect = ReconnectConfig {
        channels: vec![args.channel.clone()],
        ..Default::default()
    };

    println!("Moderation bot starting...");
    println!("  Server: {}", args.server);
    println!("  Channel: {}", args.channel);
    println!("  Commands: !ping !whoami !echo !history !greet !kick !topic !op !voice !help");
    println!("  Rate limit: 5 commands / 30s per user");
    if let Some(ref did) = args.admin_did {
        println!("  Admin DID: {did}");
    }

    let bot = std::sync::Arc::new(bot);
    client::run_with_reconnect(
        config,
        None,
        reconnect,
        move |handle: ClientHandle, event: Event| {
            let bot = bot.clone();
            Box::pin(async move {
                match &event {
                    Event::Registered { nick } => {
                        tracing::info!(nick, "Registered");
                    }
                    Event::Disconnected { reason } => {
                        tracing::warn!(reason, "Disconnected");
                    }
                    _ => {}
                }
                bot.handle_event(&handle, &event).await;
                Ok(())
            })
        },
    )
    .await
}
