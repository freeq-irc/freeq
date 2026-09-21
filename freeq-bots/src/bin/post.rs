//! One-shot message poster. Connects as a guest, joins a channel,
//! posts a single PRIVMSG, and exits. Useful for scripts and ops
//! tooling that just needs to drop a line into a room.
//!
//! Usage:
//!   cargo run --release --bin post -- \
//!     --server irc.freeq.at:6697 --tls \
//!     --channel '#avtest' --nick claude-bot \
//!     --message "hello world"

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;

#[derive(Parser)]
#[command(name = "post", about = "Post a one-shot message to a freeq channel")]
struct Args {
    #[arg(long, default_value = "irc.freeq.at:6697")]
    server: String,
    #[arg(long, default_value = "post-bot")]
    nick: String,
    #[arg(long)]
    channel: String,
    #[arg(long)]
    message: String,
    #[arg(long, default_value_t = true)]
    tls: bool,
    #[arg(long)]
    tls_insecure: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "freeq post tool".to_string(),
        tls: args.tls,
        tls_insecure: args.tls_insecure,
        web_token: None,
        websocket_url: None,
        ..Default::default()
    };

    let conn = client::establish_connection(&config)
        .await
        .with_context(|| format!("connecting to {}", args.server))?;
    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    // Wait for registration so JOIN/PRIVMSG aren't sent prematurely.
    loop {
        match tokio::time::timeout(Duration::from_secs(15), events.recv()).await {
            Ok(Some(Event::Registered { .. })) => break,
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("connection closed during registration"),
            Err(_) => anyhow::bail!("registration timeout"),
        }
    }

    handle
        .join(&args.channel)
        .await
        .with_context(|| format!("joining {}", args.channel))?;
    // Brief delay for the server to acknowledge the join.
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle
        .privmsg(&args.channel, &args.message)
        .await
        .context("posting message")?;
    // Drain a moment so the message actually leaves the socket before exit.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}
