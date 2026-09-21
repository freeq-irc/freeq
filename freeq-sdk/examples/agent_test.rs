//! Agent registration test — connects, registers as agent, joins #chad-dev.
//!
//! Usage:
//!   cargo run --example agent_test -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "agent-test", about = "Test agent registration flow")]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "pi-agent")]
    nick: String,
    #[arg(long, default_value = "#chad-dev")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    println!(
        "Connecting to {} as {} (tls={})...",
        args.server, args.nick, args.tls
    );

    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Pi Coding Agent (test)".to_string(),
        tls: args.tls,
        tls_insecure: false,
        web_token: None,
        websocket_url: None,
        ..Default::default()
    };

    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    let channel = args.channel.clone();
    let h = handle.clone();

    // After registration: register as agent, join channel, send test message
    tokio::spawn(async move {
        // Wait for registration to complete
        tokio::time::sleep(Duration::from_secs(3)).await;

        println!("Sending AGENT REGISTER...");
        if let Err(e) = h.register_agent("agent").await {
            eprintln!("Failed to register agent: {e}");
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("Joining {}...", channel);
        if let Err(e) = h.join(&channel).await {
            eprintln!("Failed to join: {e}");
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        println!("Sending test message...");
        if let Err(e) = h
            .privmsg(
                &channel,
                "🤖 Agent registration test — can you see the robot icon in the web app?",
            )
            .await
        {
            eprintln!("Failed to send: {e}");
        }

        // Stay connected for 30 seconds so the web app can observe
        println!("Staying connected for 30s so you can check the web app...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        println!("Disconnecting...");
        let _ = h.quit(Some("agent test complete")).await;
    });

    // Event loop
    loop {
        match tokio::time::timeout(Duration::from_secs(60), events.recv()).await {
            Ok(Some(event)) => {
                match &event {
                    Event::Connected => println!("✓ Connected"),
                    Event::Registered { nick } => println!("✓ Registered as {nick}"),
                    Event::Joined { channel, .. } => println!("✓ Joined {channel}"),
                    Event::Message {
                        from, target, text, ..
                    } => {
                        println!("  [{target}] <{from}> {text}");
                    }
                    Event::ServerNotice { text } => {
                        println!("  NOTICE: {text}");
                    }
                    Event::RawLine(line) => {
                        // Show agent-related raw lines
                        let l = line.as_str();
                        if l.contains("AGENT")
                            || l.contains("actor")
                            || l.contains("673")
                            || l.contains("NOTICE")
                        {
                            println!("  RAW: {}", l.trim());
                        }
                    }
                    Event::Disconnected { reason } => {
                        println!("✗ Disconnected: {reason}");
                        break;
                    }
                    _ => {}
                }
            }
            Ok(None) => {
                println!("Event channel closed");
                break;
            }
            Err(_) => {
                println!("Timeout waiting for events");
                break;
            }
        }
    }

    Ok(())
}
