#!/usr/bin/env rust-script
//! Demo bot that authenticates with did:key and registers as an agent.
//! Usage: cargo run --bin demo-bot

use std::sync::Arc;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ConnectConfig, Event};
use freeq_sdk::crypto::PrivateKey;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Load bot identity
    let key_path = std::env::var("BOT_KEY")
        .unwrap_or_else(|_| {
            let home = dirs::home_dir().unwrap();
            home.join(".freeq/bots/demo-bot/key.ed25519").to_string_lossy().to_string()
        });
    let identity_path = std::env::var("BOT_IDENTITY")
        .unwrap_or_else(|_| {
            let home = dirs::home_dir().unwrap();
            home.join(".freeq/bots/demo-bot/identity.json").to_string_lossy().to_string()
        });

    let key_bytes = std::fs::read(&key_path)?;
    let private_key = PrivateKey::ed25519_from_bytes(&key_bytes)?;

    let identity: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&identity_path)?)?;
    let did = identity["id"].as_str().unwrap().to_string();

    println!("🤖 Bot DID: {did}");
    println!("🔑 Key: {key_path}");

    let server = std::env::var("IRC_SERVER").unwrap_or_else(|_| "irc.freeq.at:6697".to_string());

    let config = ConnectConfig {
        server_addr: server,
        nick: "demo-bot".to_string(),
        user: "demo-bot".to_string(),
        realname: "FreeQ Demo Bot (agent-native Phase 1)".to_string(),
        tls: true,
        tls_insecure: false,
        web_token: None,
        ..Default::default()
    };

    let signer = Arc::new(KeySigner::new(did.clone(), private_key));
    let (handle, mut events) = client::connect(config, Some(signer));

    // Wait for registration then set up agent
    let mut registered = false;
    let mut heartbeat_task: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        match events.recv().await {
            Some(Event::Registered { nick }) => {
                println!("✅ Registered as {nick}");
                registered = true;

                // Register as agent
                handle.register_agent("agent").await?;

                // Submit provenance
                handle.submit_provenance(&serde_json::json!({
                    "name": "demo-bot",
                    "version": "0.1.0",
                    "source": "https://github.com/freeq-irc/freeq",
                    "runtime": "freeq-sdk/rust",
                    "capabilities": ["chat", "heartbeat"],
                    "created_by": "did:plc:4qsyxmnsblo4luuycm3572bq"
                })).await?;

                // Set presence
                handle.set_presence("active", Some("Ready to demo agent-native features"), None).await?;

                // Start heartbeat (every 30s)
                heartbeat_task = Some(handle.start_heartbeat(std::time::Duration::from_secs(30)));

                // Join #freeq
                handle.join("#freeq").await?;

                // Announce
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                handle.privmsg("#freeq", "👋 Hello from demo-bot! I'm an agent-native bot authenticated via did:key with SASL. Try /whois demo-bot to see my identity card.").await?;
            }
            Some(Event::Privmsg { from, target, text, .. }) => {
                if !registered { continue; }
                // Only respond to messages addressed to us
                let my_nick = "demo-bot";
                let addressed = text.starts_with(&format!("{my_nick}:"))
                    || text.starts_with(&format!("{my_nick},"));

                if addressed {
                    let msg = text.splitn(2, |c| c == ':' || c == ',').nth(1).unwrap_or("").trim();
                    let reply_target = if target.starts_with('#') { target.as_str() } else { from.as_str() };

                    match msg.to_lowercase().as_str() {
                        "ping" => {
                            handle.privmsg(reply_target, &format!("{from}: pong! 🏓")).await?;
                        }
                        "status" => {
                            handle.privmsg(reply_target, &format!("{from}: I'm an agent-native bot. DID: {did} | Class: agent | Heartbeat: 30s TTL")).await?;
                        }
                        "help" => {
                            handle.privmsg(reply_target, &format!("{from}: Commands: ping, status, help, quit")).await?;
                        }
                        "quit" => {
                            handle.privmsg(reply_target, "Goodbye! 👋").await?;
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            handle.quit(Some("Requested by user")).await?;
                            break;
                        }
                        _ => {
                            handle.privmsg(reply_target, &format!("{from}: I don't understand that. Try: demo-bot: help")).await?;
                        }
                    }
                }
            }
            Some(Event::Disconnected { reason }) => {
                println!("❌ Disconnected: {reason}");
                break;
            }
            None => {
                println!("Event channel closed");
                break;
            }
            _ => {}
        }
    }

    if let Some(task) = heartbeat_task {
        task.abort();
    }

    Ok(())
}
