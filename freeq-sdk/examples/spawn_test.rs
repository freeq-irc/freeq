//! Quick spawn test — factory spawns a child agent so you can inspect its identity card.
//! Both stay connected until you say "quit".
//!
//! Usage:
//!   cargo run --example spawn_test -- --server irc.freeq.at:6697 --tls --channel "#chad-dev"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::auth::KeySigner;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::event::Event;
use std::time::Duration;
use tokio::time::timeout;

const OWNER: &str = "chadfowler.com";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "factory")]
    nick: String,
    #[arg(long, default_value = "#chad-dev")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let ch = &args.channel;

    // Load or generate persistent ed25519 key
    let key_dir = dirs::home_dir().unwrap().join(".freeq/bots/factory");
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
    let signer = KeySigner::new(did.clone(), private_key);

    println!("Connecting as {}...", args.nick);
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Phase 2 Factory Agent".to_string(),
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
                println!("✓ Registered as {nick}");
                break;
            }
            Some(Event::Disconnected { reason }) => {
                eprintln!("✗ {reason}");
                return Ok(());
            }
            _ => continue,
        }
    }

    // Setup: register as agent, provenance, join
    handle.register_agent("agent").await?;
    handle.raw("HEARTBEAT 60").await?;
    handle
        .raw("PRESENCE :state=active;status=Spawn test")
        .await?;

    let provenance = serde_json::json!({
        "actor_did": did,
        "origin_type": "external_import",
        "creator_did": "did:plc:4qsyxmnsblo4luuycm3572bq",
        "implementation_ref": "freeq/spawn_test.rs@HEAD",
        "source_repo": "https://github.com/freeq-irc/freeq",
        "authority_basis": "Operated by server administrator",
        "revocation_authority": "did:plc:4qsyxmnsblo4luuycm3572bq",
    });
    let prov_b64 = base64_url_encode(&serde_json::to_vec(&provenance)?);
    handle.raw(&format!("PROVENANCE :{prov_b64}")).await?;

    handle.join(ch).await?;

    // Drain history
    println!("Draining history...");
    tokio::time::sleep(Duration::from_secs(4)).await;
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), events.recv()).await {}

    // Spawn a child agent
    println!("Spawning child agent...");
    handle
        .raw(&format!(
            "AGENT SPAWN {ch} :nick=factory-worker;capabilities=post_message;ttl=600;task=css-build"
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    handle
        .privmsg(
            ch,
            "👋 factory here. I just spawned factory-worker as a child agent.",
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    handle.raw(&format!("AGENT MSG factory-worker {ch} :🔨 Hi! I'm factory-worker, a spawned child of factory. Click my name to see my identity card.")).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    handle
        .privmsg(
            ch,
            "Both of us will stay connected. Click our names in the member list to inspect.",
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    handle
        .privmsg(ch, "Say 'quit' when you're done looking.")
        .await?;

    println!("Both agents connected. Waiting for 'quit'...");

    // Stay alive, heartbeat, respond to quit
    let mut last_hb = tokio::time::Instant::now();
    loop {
        let remaining = Duration::from_secs(25).saturating_sub(last_hb.elapsed());
        match timeout(remaining, events.recv()).await {
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
                if target.eq_ignore_ascii_case(ch) && from.eq_ignore_ascii_case(OWNER) {
                    let lower = text.trim().to_lowercase();
                    if lower == "quit"
                        || lower == "q"
                        || lower.ends_with(": quit")
                        || lower.ends_with(", quit")
                    {
                        break;
                    }
                }
            }
            Ok(Some(Event::Disconnected { reason })) => {
                eprintln!("Disconnected: {reason}");
                return Ok(());
            }
            Ok(_) => {}
            Err(_) => {
                // Timeout — send heartbeat
                handle.raw("HEARTBEAT 60").await?;
                last_hb = tokio::time::Instant::now();
            }
        }
    }

    println!("Cleaning up...");
    handle
        .privmsg(ch, "👋 Despawning factory-worker and signing off.")
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.raw("AGENT DESPAWN factory-worker").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.raw("PRESENCE :state=offline;status=Done").await?;
    handle.quit(Some("spawn test complete")).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Done.");
    Ok(())
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
